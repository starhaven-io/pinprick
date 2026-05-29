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
}

/// Cap on how long we'll sleep waiting for a rate-limit reset. Longer waits
/// would make `pin` / `update` appear hung from the user's perspective.
const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(60);

/// Delay before retrying a transient 5xx or network error.
const TRANSIENT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Total per-request timeout. Without one, a stalled connection hangs the whole
/// run forever (the retry logic only fires on a completed response).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection-establishment timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a single buffered response body. Action source files and
/// recursive trees are fetched from arbitrary repositories; a hostile or
/// compromised endpoint could otherwise stream gigabytes into memory.
pub(crate) const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Build the shared HTTP client used for every outbound request: bounded
/// request/connect timeouts so a stalled endpoint can't hang the run, and an
/// explicit (bounded) redirect policy. reqwest strips the `Authorization`
/// header on cross-host redirects, so following GitHub's content redirects is
/// safe.
pub(crate) fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("failed to build HTTP client")
}

/// Read a response body into memory, failing if it exceeds [`MAX_RESPONSE_BYTES`].
/// Streams chunk-by-chunk so an oversized body is rejected before it is fully
/// buffered. Use for the unbounded-size fetches (action source, file trees,
/// the remote catalog); the fixed-shape GitHub API responses don't need it.
pub(crate) async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading response body")? {
        within_cap(buf.len(), chunk.len(), MAX_RESPONSE_BYTES)?;
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Error if appending `incoming` bytes to a buffer already holding `current`
/// would exceed `max`. Split out from [`read_capped`] so the boundary logic is
/// unit-testable without constructing a streaming response.
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

#[derive(Deserialize)]
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
        }
    }

    async fn send_once(&self, url: &str) -> reqwest::Result<reqwest::Response> {
        self.client
            .get(url)
            .header(USER_AGENT, "pinprick")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response> {
        // Up to two attempts: the first may hit a transient error or a
        // rate-limit reset that's imminent; the second is the real answer.
        for attempt in 0..2u8 {
            let last_attempt = attempt == 1;

            let resp = match self.send_once(url).await {
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
                    // Secondary/abuse rate limit: GitHub returns 403/429 with a
                    // `Retry-After` header and no zeroed `x-ratelimit-remaining`.
                    // The concurrent source-fetch fan-out is what trips these.
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

    /// Resolve a tag to its commit SHA, following annotated tag objects.
    pub async fn resolve_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<String> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag}");
        let resp = self.get(&url).await?;

        if resp.status().as_u16() == 404 {
            bail!(GitHubError::TagNotFound {
                owner: owner.into(),
                repo: repo.into(),
                tag: tag.into(),
            });
        }

        let git_ref: GitRef = resp.json().await.context("parsing tag ref response")?;

        // If it's an annotated tag, follow to the commit
        if git_ref.object.object_type == "tag" {
            let tag_url = format!(
                "https://api.github.com/repos/{owner}/{repo}/git/tags/{}",
                git_ref.object.sha
            );
            let tag_resp = self.get(&tag_url).await?;
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
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/git/matching-refs/tags/{original_tag}"
        );
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
        let url = format!("https://api.github.com/repos/{owner}/{repo}/git/tags/{tag_sha}");
        let Ok(resp) = self.get(&url).await else {
            return String::new();
        };
        resp.json::<TagObject>()
            .await
            .map(|t| t.object.sha)
            .unwrap_or_default()
    }

    /// List releases for a repo (first page, most recent first).
    pub async fn list_releases(&self, owner: &str, repo: &str) -> Result<Vec<Release>> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/releases?per_page=30");
        let resp = self.get(&url).await?;

        if resp.status().as_u16() == 404 {
            bail!(GitHubError::RepoNotFound {
                owner: owner.into(),
                repo: repo.into(),
            });
        }

        let releases: Vec<Release> = resp.json().await.context("parsing releases")?;
        Ok(releases)
    }

    /// Find a tag name pointing at the given commit SHA, if any. Queries
    /// the first 100 tags only — pinned actions are virtually always on a
    /// recent release tag, and paginating further isn't worth the latency.
    pub async fn sha_to_tag(&self, owner: &str, repo: &str, sha: &str) -> Result<Option<String>> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/tags?per_page=100");
        let resp = self.get(&url).await?;
        if resp.status().as_u16() == 404 {
            bail!(GitHubError::RepoNotFound {
                owner: owner.into(),
                repo: repo.into(),
            });
        }
        let tags: Vec<TagListEntry> = resp.json().await.context("parsing tags")?;
        Ok(tags
            .into_iter()
            .find(|t| t.commit.sha == sha)
            .map(|t| t.name))
    }

    /// List published security advisories for the repo. Draft and withdrawn
    /// advisories are excluded server-side via the `state` filter.
    pub async fn list_security_advisories(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<SecurityAdvisory>> {
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/security-advisories?state=published&per_page=100"
        );
        let resp = self.get(&url).await?;
        if resp.status().as_u16() == 404 {
            // Some repos disable advisories or don't have any — treat as empty.
            return Ok(Vec::new());
        }
        let advisories: Vec<SecurityAdvisory> =
            resp.json().await.context("parsing security advisories")?;
        Ok(advisories)
    }

    /// Return `true` if the repo is archived on GitHub.
    pub async fn is_archived(&self, owner: &str, repo: &str) -> Result<bool> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}");
        let resp = self.get(&url).await?;

        if resp.status().as_u16() == 404 {
            bail!(GitHubError::RepoNotFound {
                owner: owner.into(),
                repo: repo.into(),
            });
        }

        let repo: Repository = resp.json().await.context("parsing repository metadata")?;
        Ok(repo.archived)
    }

    /// Fetch the file tree for a repo at a given SHA.
    pub async fn fetch_tree(&self, owner: &str, repo: &str, sha: &str) -> Result<Vec<TreeEntry>> {
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1");
        let resp = self.get(&url).await?;
        if resp.status().as_u16() == 404 {
            bail!(GitHubError::RepoNotFound {
                owner: owner.into(),
                repo: repo.into(),
            });
        }
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
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={git_ref}");
        let resp = self
            .client
            .get(&url)
            .header(USER_AGENT, "pinprick")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, "application/vnd.github.raw+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("fetching file content")?;

        if resp.status().as_u16() == 404 {
            bail!("File {path} not found in {owner}/{repo} at {git_ref}");
        }

        let bytes = read_capped(resp).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
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

/// Parse the `Retry-After` header (an integer count of seconds) that GitHub
/// sends on secondary/abuse rate limits. Returns `None` if the header is absent
/// or in the HTTP-date form (which GitHub does not use for these limits).
fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    parse_retry_after(resp.headers().get("retry-after")?.to_str().ok()?)
}

/// Parse a `Retry-After` header value as an integer count of seconds. Returns
/// `None` for the HTTP-date form, which GitHub does not use for these limits.
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
}
