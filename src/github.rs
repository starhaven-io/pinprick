use anyhow::{Context, Result, bail};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cloning is cheap: `reqwest::Client` shares its connection pool across
/// clones (it's `Arc`-backed internally), so clones reuse connections. This
/// lets the audit fan out per-file fetches across concurrent tasks.
#[derive(Clone)]
pub struct GitHubClient {
    client: reqwest::Client,
    token: String,
    /// API origin, always `https://api.github.com` in production. The
    /// `#[cfg(test)]` constructor is the only way to point this elsewhere, so
    /// production code can never be aimed at an attacker-controlled host.
    base: String,
}

const GITHUB_API_BASE: &str = "https://api.github.com";

const ACCEPT_JSON: &str = "application/vnd.github+json";

/// Asks the contents API for the raw file body instead of the base64 wrapper.
const ACCEPT_RAW: &str = "application/vnd.github.raw+json";

/// Cap on how long we'll sleep waiting for a rate-limit reset. Longer waits
/// would make `pin` / `update` appear hung from the user's perspective.
const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(60);

const TRANSIENT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Total per-request timeout — without one a stalled connection hangs forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const LIST_PAGE_SIZE: usize = 100;
const MAX_LIST_PAGES: usize = 10;

/// Cap on a buffered response body — a hostile endpoint could otherwise stream
/// gigabytes of "action source" into memory.
pub(crate) const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Shared HTTP client with request/connect timeouts (a stalled endpoint can't
/// hang the run) and a bounded redirect policy. reqwest strips `Authorization`
/// on cross-host redirects, so following GitHub's content redirects is safe.
pub(crate) fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("failed to build HTTP client")
}

/// Read a response body, rejecting it past [`MAX_RESPONSE_BYTES`] before it is
/// fully buffered. For the unbounded-size fetches (action source, trees, the
/// remote catalog).
pub(crate) async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading response body")? {
        within_cap(buf.len(), chunk.len(), MAX_RESPONSE_BYTES)?;
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// The cap check, split from [`read_capped`] so it's unit-testable without a
/// streaming response.
fn within_cap(current: usize, incoming: usize, max: usize) -> Result<()> {
    if current + incoming > max {
        bail!("response body exceeds {max} bytes — refusing to buffer");
    }
    Ok(())
}

#[derive(Deserialize)]
struct GitRef {
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type")]
    object_type: String,
}

#[derive(Deserialize)]
struct TagObject {
    object: TagTarget,
}

#[derive(Deserialize)]
struct TagTarget {
    sha: String,
}

#[derive(Deserialize)]
struct MatchingRef {
    #[serde(rename = "ref")]
    ref_name: String,
    object: GitObject,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub html_url: Option<String>,
}

#[derive(Deserialize)]
struct Tree {
    tree: Vec<TreeEntry>,
}

#[derive(Deserialize)]
struct Repository {
    archived: bool,
}

#[derive(Debug, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
}

#[derive(Deserialize)]
struct TagListEntry {
    name: String,
    commit: TagListCommit,
}

#[derive(Deserialize)]
struct TagListCommit {
    sha: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityAdvisory {
    pub ghsa_id: String,
    pub html_url: String,
    pub severity: String,
    #[serde(default)]
    pub summary: String,
    pub vulnerabilities: Vec<AdvisoryVulnerability>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryVulnerability {
    /// The affected package. One advisory can list several packages (e.g. an
    /// action *and* a CLI); the scorer must only match the entry for the action
    /// it is checking, or a different package's range can false-match.
    #[serde(default)]
    pub package: Option<AdvisoryPackage>,
    pub vulnerable_version_range: Option<String>,
    pub patched_versions: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryPackage {
    /// For the GitHub Actions ecosystem this is `owner/repo`.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
    #[error("Authentication required")]
    AuthRequired,
    #[error("Rate limit exceeded")]
    RateLimit,
    #[error("Repository '{owner}/{repo}' not found")]
    RepoNotFound { owner: String, repo: String },
    #[error("Tag '{tag}' not found in {owner}/{repo}")]
    TagNotFound {
        owner: String,
        repo: String,
        tag: String,
    },
}

impl GitHubClient {
    pub fn new(token: String) -> Self {
        Self {
            client: build_client(),
            token,
            base: GITHUB_API_BASE.to_string(),
        }
    }

    /// Build a client pointed at an arbitrary API origin. Test-only: it exists
    /// to aim the client at a local mock server, and is gated so production
    /// code keeps the `https://api.github.com` invariant.
    #[cfg(test)]
    pub(crate) fn with_base(token: String, base: String) -> Self {
        Self {
            client: build_client(),
            token,
            base,
        }
    }

    async fn send_once(&self, url: &str, accept: &str) -> reqwest::Result<reqwest::Response> {
        self.client
            .get(url)
            .header(USER_AGENT, "pinprick")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, accept)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response> {
        self.get_with_accept(url, ACCEPT_JSON).await
    }

    async fn get_with_accept(&self, url: &str, accept: &str) -> Result<reqwest::Response> {
        // Up to two attempts: the first may hit a transient error or a
        // rate-limit reset that's imminent; the second is the real answer.
        for attempt in 0..2u8 {
            let last_attempt = attempt == 1;

            let resp = match self.send_once(url, accept).await {
                Ok(r) => r,
                Err(e) if last_attempt => {
                    return Err(e).context("GitHub API request failed");
                }
                Err(_) => {
                    tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                    continue;
                }
            };

            match resp.status().as_u16() {
                401 => bail!(GitHubError::AuthRequired),
                403 if is_rate_limited(&resp) => {
                    if let Some(wait) = rate_limit_wait(&resp)
                        && wait <= MAX_RATE_LIMIT_WAIT
                        && !last_attempt
                    {
                        // +1s so we don't wake exactly at reset and race the clock.
                        tokio::time::sleep(wait + Duration::from_secs(1)).await;
                        continue;
                    }
                    bail!(GitHubError::RateLimit);
                }
                403 | 429 if retry_after(&resp).is_some() => {
                    // Secondary/abuse rate limit: `Retry-After` with no zeroed
                    // `x-ratelimit-remaining` (the concurrent fan-out trips these).
                    if let Some(wait) = retry_after(&resp)
                        && wait <= MAX_RATE_LIMIT_WAIT
                        && !last_attempt
                    {
                        tokio::time::sleep(wait + Duration::from_secs(1)).await;
                        continue;
                    }
                    bail!(GitHubError::RateLimit);
                }
                500..=599 if !last_attempt => {
                    tokio::time::sleep(TRANSIENT_RETRY_DELAY).await;
                    continue;
                }
                _ => return Ok(resp),
            }
        }
        unreachable!("loop always returns or continues until last_attempt")
    }

    /// Base URL for a repo's API routes, with owner and repo percent-encoded
    /// so a crafted `uses:` ref can't reshape the request path.
    fn repo_url(&self, owner: &str, repo: &str) -> Result<String> {
        Ok(format!(
            "{}/repos/{}/{}",
            self.base,
            encode_path_segment(owner)?,
            encode_path_segment(repo)?
        ))
    }

    /// Resolve a tag to its commit SHA, following annotated tag objects.
    pub async fn resolve_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<String> {
        // Tags may legitimately contain `/` (e.g. `release/v1.2`), so encode
        // per segment rather than as a single component.
        let url = format!(
            "{}/git/ref/tags/{}",
            self.repo_url(owner, repo)?,
            percent_encode_path(tag)?
        );
        let resp = self.get(&url).await?;

        if resp.status().as_u16() == 404 {
            bail!(GitHubError::TagNotFound {
                owner: owner.into(),
                repo: repo.into(),
                tag: tag.into(),
            });
        }
        ensure_success(&resp, format!("resolving tag {tag} in {owner}/{repo}"))?;

        let git_ref: GitRef = resp.json().await.context("parsing tag ref response")?;

        if git_ref.object.object_type == "tag" {
            let tag_url = format!(
                "{}/git/tags/{}",
                self.repo_url(owner, repo)?,
                encode_path_segment(&git_ref.object.sha)?
            );
            let tag_resp = self.get(&tag_url).await?;
            ensure_success(
                &tag_resp,
                format!("resolving annotated tag {tag} in {owner}/{repo}"),
            )?;
            let tag_obj: TagObject = tag_resp.json().await.context("parsing tag object")?;
            Ok(tag_obj.object.sha)
        } else {
            Ok(git_ref.object.sha)
        }
    }

    /// Find the most specific tag pointing at a given SHA.
    /// e.g., if `v4` and `v4.2.1` both resolve to the same commit, returns `v4.2.1`.
    pub async fn find_exact_tag(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        original_tag: &str,
    ) -> String {
        let Ok(base) = self.repo_url(owner, repo) else {
            return original_tag.to_string();
        };
        let Ok(encoded_tag) = percent_encode_path(original_tag) else {
            return original_tag.to_string();
        };
        let url = format!("{base}/git/matching-refs/tags/{encoded_tag}");
        let Ok(resp) = self.get(&url).await else {
            return original_tag.to_string();
        };
        let Ok(refs) = resp.json::<Vec<MatchingRef>>().await else {
            return original_tag.to_string();
        };

        let mut best = original_tag.to_string();
        for r in &refs {
            let tag_name = r.ref_name.strip_prefix("refs/tags/").unwrap_or(&r.ref_name);
            let resolved = if r.object.object_type == "tag" {
                self.resolve_annotated_tag(owner, repo, &r.object.sha).await
            } else {
                r.object.sha.clone()
            };

            if resolved == sha && tag_name.len() > best.len() {
                best = tag_name.to_string();
            }
        }

        best
    }

    async fn resolve_annotated_tag(&self, owner: &str, repo: &str, tag_sha: &str) -> String {
        let (Ok(base), Ok(encoded_sha)) =
            (self.repo_url(owner, repo), encode_path_segment(tag_sha))
        else {
            return String::new();
        };
        let url = format!("{base}/git/tags/{encoded_sha}");
        let Ok(resp) = self.get(&url).await else {
            return String::new();
        };
        resp.json::<TagObject>()
            .await
            .map(|t| t.object.sha)
            .unwrap_or_default()
    }

    /// List releases for a repo (bounded pagination, most recent first).
    pub async fn list_releases(&self, owner: &str, repo: &str) -> Result<Vec<Release>> {
        let base = self.repo_url(owner, repo)?;
        let mut releases = Vec::new();
        for page in 1..=MAX_LIST_PAGES {
            let url = format!("{base}/releases?per_page={LIST_PAGE_SIZE}&page={page}");
            let resp = self.get(&url).await?;

            if resp.status().as_u16() == 404 {
                bail!(GitHubError::RepoNotFound {
                    owner: owner.into(),
                    repo: repo.into(),
                });
            }
            ensure_success(&resp, format!("listing releases for {owner}/{repo}"))?;

            let mut page_releases: Vec<Release> = resp.json().await.context("parsing releases")?;
            let done = page_releases.len() < LIST_PAGE_SIZE;
            releases.append(&mut page_releases);
            if done {
                break;
            }
        }
        Ok(releases)
    }

    /// Fetch the tag list for a repo (bounded pagination).
    async fn fetch_tags(&self, owner: &str, repo: &str) -> Result<Vec<TagListEntry>> {
        let base = self.repo_url(owner, repo)?;
        let mut tags = Vec::new();
        for page in 1..=MAX_LIST_PAGES {
            let url = format!("{base}/tags?per_page={LIST_PAGE_SIZE}&page={page}");
            let resp = self.get(&url).await?;
            if resp.status().as_u16() == 404 {
                bail!(GitHubError::RepoNotFound {
                    owner: owner.into(),
                    repo: repo.into(),
                });
            }
            ensure_success(&resp, format!("listing tags for {owner}/{repo}"))?;
            let mut page_tags: Vec<TagListEntry> = resp.json().await.context("parsing tags")?;
            let done = page_tags.len() < LIST_PAGE_SIZE;
            tags.append(&mut page_tags);
            if done {
                break;
            }
        }
        Ok(tags)
    }

    /// Find a tag name pointing at the given commit SHA, if any. A release
    /// commit typically carries several tags (`v4`, `v4.2`, `v4.2.1`, maybe
    /// `nightly`); prefer the most specific version-like name — mirroring
    /// `find_exact_tag` — so callers compare against `v4.2.1` rather than a
    /// sliding `v4` or a moving `nightly`.
    pub async fn sha_to_tag(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>> {
        let names: Vec<String> = self
            .fetch_tags(owner, repo)
            .await?
            .into_iter()
            .filter(|t| t.commit.sha == sha)
            .map(|t| t.name)
            .collect();
        Ok(names
            .iter()
            .filter(|t| is_version_like_tag(t))
            .max_by_key(|t| t.len())
            .cloned()
            .or_else(|| names.into_iter().next()))
    }

    /// List tag names for a repo. The `update` command falls back to this when
    /// a repo publishes tags but no GitHub Releases (e.g.
    /// `actions/upload-code-coverage`), so the release feed reports nothing.
    pub async fn list_tags(&self, owner: &str, repo: &str) -> Result<Vec<String>> {
        Ok(self
            .fetch_tags(owner, repo)
            .await?
            .into_iter()
            .map(|t| t.name)
            .collect())
    }

    /// List published security advisories for the repo. Draft and withdrawn
    /// advisories are excluded server-side via the `state` filter.
    pub async fn list_security_advisories(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<SecurityAdvisory>> {
        let url = format!(
            "{}/security-advisories?state=published&per_page=100",
            self.repo_url(owner, repo)?
        );
        let resp = self.get(&url).await?;
        if resp.status().as_u16() == 404 {
            // Some repos disable advisories or don't have any — treat as empty.
            return Ok(Vec::new());
        }
        ensure_success(
            &resp,
            format!("listing security advisories for {owner}/{repo}"),
        )?;
        let advisories: Vec<SecurityAdvisory> =
            resp.json().await.context("parsing security advisories")?;
        Ok(advisories)
    }

    /// Return `true` if the repo is archived on GitHub.
    pub async fn is_archived(&self, owner: &str, repo: &str) -> Result<bool> {
        let url = self.repo_url(owner, repo)?;
        let resp = self.get(&url).await?;

        if resp.status().as_u16() == 404 {
            bail!(GitHubError::RepoNotFound {
                owner: owner.into(),
                repo: repo.into(),
            });
        }
        ensure_success(&resp, format!("fetching metadata for {owner}/{repo}"))?;

        let repo: Repository = resp.json().await.context("parsing repository metadata")?;
        Ok(repo.archived)
    }

    /// Fetch the file tree for a repo at a given SHA.
    pub async fn fetch_tree(&self, owner: &str, repo: &str, sha: &str) -> Result<Vec<TreeEntry>> {
        let url = format!(
            "{}/git/trees/{}?recursive=1",
            self.repo_url(owner, repo)?,
            encode_path_segment(sha)?
        );
        let resp = self.get(&url).await?;
        if resp.status().as_u16() == 404 {
            bail!(GitHubError::RepoNotFound {
                owner: owner.into(),
                repo: repo.into(),
            });
        }
        ensure_success(&resp, format!("fetching tree for {owner}/{repo}@{sha}"))?;
        let bytes = read_capped(resp).await?;
        let tree: Tree = serde_json::from_slice(&bytes).context("parsing tree")?;
        Ok(tree.tree)
    }

    /// Fetch raw file content from a repo at a given ref.
    pub async fn fetch_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        git_ref: &str,
    ) -> Result<String> {
        let encoded_path = percent_encode_path(path)?;
        let encoded_ref = percent_encode_component(git_ref);
        let url = format!(
            "{}/contents/{encoded_path}?ref={encoded_ref}",
            self.repo_url(owner, repo)?
        );
        let resp = self.get_with_accept(&url, ACCEPT_RAW).await?;

        if resp.status().as_u16() == 404 {
            bail!("File {path} not found in {owner}/{repo} at {git_ref}");
        }
        if !resp.status().is_success() {
            bail!(
                "GitHub API returned {} while fetching {path} in {owner}/{repo} at {git_ref}",
                resp.status()
            );
        }

        let bytes = read_capped(resp).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn percent_encode_path(path: &str) -> Result<String> {
    Ok(path
        .split('/')
        .map(encode_path_segment)
        .collect::<Result<Vec<_>>>()?
        .join("/"))
}

/// Percent-encode a single URL path segment, rejecting dot-segments. The
/// WHATWG URL parser collapses `.`/`..` segments even when percent-encoded,
/// so a crafted value could climb out of its path position; git and GitHub
/// both forbid such names, so refusing them loses nothing.
fn encode_path_segment(value: &str) -> Result<String> {
    if value == "." || value == ".." {
        bail!("invalid path segment {value:?}");
    }
    Ok(percent_encode_component(value))
}

fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Whether a tag looks like a version (optional `v` followed by a digit).
/// Mirrors `update::is_version_like`.
fn is_version_like_tag(tag: &str) -> bool {
    tag.strip_prefix('v')
        .unwrap_or(tag)
        .starts_with(|c: char| c.is_ascii_digit())
}

fn ensure_success(resp: &reqwest::Response, operation: String) -> Result<()> {
    if !resp.status().is_success() {
        bail!("GitHub API returned {} while {operation}", resp.status());
    }
    Ok(())
}

/// True if the response's `x-ratelimit-remaining` is exactly zero — GitHub's
/// signal that further requests will be rejected until `x-ratelimit-reset`.
fn is_rate_limited(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "0")
}

/// Seconds from now until the rate-limit window resets, per the response's
/// `x-ratelimit-reset` epoch-seconds header. Returns `None` if the header is
/// missing or unparsable.
fn rate_limit_wait(resp: &reqwest::Response) -> Option<Duration> {
    let reset_at: u64 = resp
        .headers()
        .get("x-ratelimit-reset")?
        .to_str()
        .ok()?
        .parse()
        .ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset_at.saturating_sub(now)))
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    parse_retry_after(resp.headers().get("retry-after")?.to_str().ok()?)
}

/// Parse a `Retry-After` value as an integer count of seconds — the form
/// GitHub sends on secondary/abuse rate limits. Returns `None` for the
/// HTTP-date form, which GitHub does not use for these limits.
fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_cap_allows_up_to_the_limit() {
        assert!(within_cap(0, 100, 100).is_ok());
        assert!(within_cap(90, 10, 100).is_ok());
        assert!(within_cap(0, 0, 0).is_ok());
    }

    #[test]
    fn within_cap_rejects_overflow() {
        assert!(within_cap(0, 101, 100).is_err());
        assert!(within_cap(100, 1, 100).is_err());
    }

    #[test]
    fn parse_retry_after_accepts_integer_seconds() {
        assert_eq!(parse_retry_after("42"), Some(Duration::from_secs(42)));
        assert_eq!(parse_retry_after("  7 "), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn parse_retry_after_rejects_non_integer() {
        assert!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT").is_none());
        assert!(parse_retry_after("").is_none());
        assert!(parse_retry_after("12.5").is_none());
    }

    #[test]
    fn build_client_does_not_panic() {
        let _ = build_client();
    }

    #[test]
    fn percent_encode_path_preserves_separators() {
        assert_eq!(
            percent_encode_path("dir/a file#x.js").unwrap(),
            "dir/a%20file%23x.js"
        );
        assert_eq!(
            percent_encode_component("refs/heads/feature?x&y"),
            "refs%2Fheads%2Ffeature%3Fx%26y"
        );
    }

    #[test]
    fn encode_path_segment_rejects_dot_segments() {
        assert!(encode_path_segment(".").is_err());
        assert!(encode_path_segment("..").is_err());
        assert!(percent_encode_path("../../etc").is_err());
        // Dotted-but-not-dot-segment values pass through.
        assert_eq!(encode_path_segment("v1.2.3").unwrap(), "v1.2.3");
    }

    mod network {
        use super::*;
        use serde_json::json;
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        async fn client_for(server: &MockServer) -> GitHubClient {
            GitHubClient::with_base("test-token".into(), server.uri())
        }

        #[tokio::test]
        async fn resolve_tag_lightweight() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/ref/tags/v1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object": { "sha": "deadbeef", "type": "commit" }
                })))
                .mount(&server)
                .await;

            let sha = client_for(&server)
                .await
                .resolve_tag("o", "r", "v1")
                .await
                .unwrap();
            assert_eq!(sha, "deadbeef");
        }

        #[tokio::test]
        async fn resolve_tag_percent_encodes_owner_repo_and_tag() {
            let server = MockServer::start().await;
            // Metacharacters in owner/repo/tag must not reshape the request
            // path; slashes inside tag names stay literal separators.
            Mock::given(method("GET"))
                .and(path("/repos/o%23x/r%3Fx/git/ref/tags/release/v1%20x"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object": { "sha": "deadbeef", "type": "commit" }
                })))
                .mount(&server)
                .await;

            let sha = client_for(&server)
                .await
                .resolve_tag("o#x", "r?x", "release/v1 x")
                .await
                .unwrap();
            assert_eq!(sha, "deadbeef");
        }

        #[tokio::test]
        async fn resolve_tag_rejects_dot_segment_components() {
            // No mock mounted: a dot-segment owner or tag must error before
            // any request is sent, not climb the API path.
            let server = MockServer::start().await;
            let client = client_for(&server).await;
            assert!(client.resolve_tag("..", "r", "v1").await.is_err());
            assert!(client.resolve_tag("o", "r", "../../x").await.is_err());
            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        #[tokio::test]
        async fn resolve_tag_follows_annotated_object() {
            let server = MockServer::start().await;
            // A `tag` object type means the ref points at an annotated tag; the
            // commit lives behind a second dereference.
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/ref/tags/v1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object": { "sha": "tagobjsha", "type": "tag" }
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/tags/tagobjsha"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object": { "sha": "commitsha" }
                })))
                .mount(&server)
                .await;

            let sha = client_for(&server)
                .await
                .resolve_tag("o", "r", "v1")
                .await
                .unwrap();
            assert_eq!(sha, "commitsha");
        }

        #[tokio::test]
        async fn resolve_tag_missing_is_tag_not_found() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/ref/tags/nope"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            let err = client_for(&server)
                .await
                .resolve_tag("o", "r", "nope")
                .await
                .unwrap_err();
            assert!(matches!(
                err.downcast_ref::<GitHubError>(),
                Some(GitHubError::TagNotFound { .. })
            ));
        }

        #[tokio::test]
        async fn list_releases_parses_and_404_is_repo_not_found() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/releases"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "tag_name": "v2", "draft": false, "prerelease": false, "html_url": "u2" },
                    { "tag_name": "v1", "draft": false, "prerelease": false, "html_url": null }
                ])))
                .mount(&server)
                .await;
            let releases = client_for(&server)
                .await
                .list_releases("o", "r")
                .await
                .unwrap();
            assert_eq!(releases.len(), 2);
            assert_eq!(releases[0].tag_name, "v2");

            let missing = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/releases"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&missing)
                .await;
            let err = client_for(&missing)
                .await
                .list_releases("o", "r")
                .await
                .unwrap_err();
            assert!(matches!(
                err.downcast_ref::<GitHubError>(),
                Some(GitHubError::RepoNotFound { .. })
            ));
        }

        #[tokio::test]
        async fn list_releases_non_success_is_error_before_parse() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/releases"))
                .respond_with(ResponseTemplate::new(422).set_body_string("not json"))
                .mount(&server)
                .await;

            let err = client_for(&server)
                .await
                .list_releases("o", "r")
                .await
                .unwrap_err();
            assert!(err.to_string().contains("GitHub API returned 422"));
            assert!(err.to_string().contains("listing releases"));
        }

        #[tokio::test]
        async fn list_releases_paginates_bounded_pages() {
            let server = MockServer::start().await;
            let first_page: Vec<_> = (0..100)
                .map(|i| {
                    json!({
                        "tag_name": format!("v1.0.{i}"),
                        "draft": false,
                        "prerelease": false,
                        "html_url": null
                    })
                })
                .collect();
            Mock::given(method("GET"))
                .and(path("/repos/o/r/releases"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(first_page))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/releases"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "tag_name": "v2.0.0", "draft": false, "prerelease": false, "html_url": null }
                ])))
                .mount(&server)
                .await;

            let releases = client_for(&server)
                .await
                .list_releases("o", "r")
                .await
                .unwrap();
            assert_eq!(releases.len(), 101);
            assert_eq!(releases.last().unwrap().tag_name, "v2.0.0");
        }

        #[tokio::test]
        async fn sha_to_tag_finds_match_or_none() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v1", "commit": { "sha": "aaa" } },
                    { "name": "v2", "commit": { "sha": "bbb" } }
                ])))
                .mount(&server)
                .await;
            let c = client_for(&server).await;
            assert_eq!(
                c.sha_to_tag("o", "r", "bbb").await.unwrap().as_deref(),
                Some("v2")
            );
            assert_eq!(c.sha_to_tag("o", "r", "zzz").await.unwrap(), None);
        }

        #[tokio::test]
        async fn sha_to_tag_prefers_most_specific_version_tag() {
            let server = MockServer::start().await;
            // nightly, v4, and v4.2.1 all point at the release commit — the
            // caller must see v4.2.1, not whichever the API listed first.
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "nightly", "commit": { "sha": "aaa" } },
                    { "name": "v4", "commit": { "sha": "aaa" } },
                    { "name": "v4.2.1", "commit": { "sha": "aaa" } },
                    { "name": "stable", "commit": { "sha": "bbb" } }
                ])))
                .mount(&server)
                .await;
            let c = client_for(&server).await;
            assert_eq!(
                c.sha_to_tag("o", "r", "aaa").await.unwrap().as_deref(),
                Some("v4.2.1")
            );
            // No version-like tag at the SHA: fall back to the first match.
            assert_eq!(
                c.sha_to_tag("o", "r", "bbb").await.unwrap().as_deref(),
                Some("stable")
            );
        }

        #[tokio::test]
        async fn sha_to_tag_searches_later_tag_pages() {
            let server = MockServer::start().await;
            let first_page: Vec<_> = (0..100)
                .map(|i| json!({ "name": format!("v0.0.{i}"), "commit": { "sha": "old" } }))
                .collect();
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(first_page))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v9.9.9", "commit": { "sha": "target" } }
                ])))
                .mount(&server)
                .await;

            assert_eq!(
                client_for(&server)
                    .await
                    .sha_to_tag("o", "r", "target")
                    .await
                    .unwrap()
                    .as_deref(),
                Some("v9.9.9")
            );
        }

        #[tokio::test]
        async fn list_tags_returns_names() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v1.3.0", "commit": { "sha": "aaa" } },
                    { "name": "v1", "commit": { "sha": "aaa" } }
                ])))
                .mount(&server)
                .await;
            let tags = client_for(&server).await.list_tags("o", "r").await.unwrap();
            assert_eq!(tags, vec!["v1.3.0".to_string(), "v1".to_string()]);
        }

        #[tokio::test]
        async fn is_archived_reads_repo_metadata() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "archived": true })))
                .mount(&server)
                .await;
            assert!(
                client_for(&server)
                    .await
                    .is_archived("o", "r")
                    .await
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn list_security_advisories_404_is_empty() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/security-advisories"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
            let advs = client_for(&server)
                .await
                .list_security_advisories("o", "r")
                .await
                .unwrap();
            assert!(advs.is_empty());
        }

        #[tokio::test]
        async fn fetch_tree_and_file() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/trees/sha"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "tree": [ { "path": "action.yml", "type": "blob" } ]
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/contents/action.yml"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string("runs:\n  using: node20\n"),
                )
                .mount(&server)
                .await;

            let c = client_for(&server).await;
            let tree = c.fetch_tree("o", "r", "sha").await.unwrap();
            assert_eq!(tree[0].path, "action.yml");
            let body = c.fetch_file("o", "r", "action.yml", "sha").await.unwrap();
            assert!(body.contains("using: node20"));
        }

        #[tokio::test]
        async fn fetch_file_percent_encodes_path_and_ref() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/contents/dir/a%20file%23x.js"))
                .and(query_param("ref", "refs/heads/feature?x&y"))
                .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                .mount(&server)
                .await;

            let body = client_for(&server)
                .await
                .fetch_file("o", "r", "dir/a file#x.js", "refs/heads/feature?x&y")
                .await
                .unwrap();
            assert_eq!(body, "ok");
        }

        #[tokio::test]
        async fn fetch_tree_non_success_is_error_before_parse() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/trees/sha"))
                .respond_with(ResponseTemplate::new(422).set_body_string("not json"))
                .mount(&server)
                .await;

            let err = client_for(&server)
                .await
                .fetch_tree("o", "r", "sha")
                .await
                .unwrap_err();
            assert!(err.to_string().contains("GitHub API returned 422"));
            assert!(err.to_string().contains("fetching tree"));
        }

        #[tokio::test]
        async fn primary_rate_limit_bails_when_reset_is_far_off() {
            let server = MockServer::start().await;
            // remaining=0 with a reset well beyond MAX_RATE_LIMIT_WAIT: the
            // client must surface RateLimit immediately rather than sleep.
            let reset = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 9_999;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/ref/tags/v1"))
                .respond_with(
                    ResponseTemplate::new(403)
                        .insert_header("x-ratelimit-remaining", "0")
                        .insert_header("x-ratelimit-reset", reset.to_string().as_str()),
                )
                .mount(&server)
                .await;
            let err = client_for(&server)
                .await
                .resolve_tag("o", "r", "v1")
                .await
                .unwrap_err();
            assert!(matches!(
                err.downcast_ref::<GitHubError>(),
                Some(GitHubError::RateLimit)
            ));
        }

        #[tokio::test]
        async fn fetch_file_retries_secondary_rate_limit() {
            let server = MockServer::start().await;
            // Secondary rate limit (Retry-After without a zeroed
            // x-ratelimit-remaining) on the raw-content path: fetch_file must
            // share get()'s wait-and-retry instead of surfacing the 403 body.
            Mock::given(method("GET"))
                .and(path("/repos/o/r/contents/action.yml"))
                .respond_with(ResponseTemplate::new(403).insert_header("retry-after", "1"))
                .up_to_n_times(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/contents/action.yml"))
                .and(header("accept", "application/vnd.github.raw+json"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string("runs:\n  using: node20\n"),
                )
                .with_priority(2)
                .mount(&server)
                .await;

            let body = client_for(&server)
                .await
                .fetch_file("o", "r", "action.yml", "sha")
                .await
                .unwrap();
            assert!(body.contains("using: node20"));
        }

        #[tokio::test]
        async fn fetch_file_non_success_is_error() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/contents/action.yml"))
                .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
                .mount(&server)
                .await;

            let err = client_for(&server)
                .await
                .fetch_file("o", "r", "action.yml", "sha")
                .await
                .unwrap_err();
            assert!(err.to_string().contains("GitHub API returned 500"));
        }

        #[tokio::test]
        async fn transient_5xx_is_retried_then_succeeds() {
            let server = MockServer::start().await;
            // First attempt 500 (higher priority, single-use), second 200.
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/ref/tags/v1"))
                .respond_with(ResponseTemplate::new(500))
                .up_to_n_times(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/git/ref/tags/v1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "object": { "sha": "recovered", "type": "commit" }
                })))
                .with_priority(2)
                .mount(&server)
                .await;

            let sha = client_for(&server)
                .await
                .resolve_tag("o", "r", "v1")
                .await
                .unwrap();
            assert_eq!(sha, "recovered");
        }
    }
}
