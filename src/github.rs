use anyhow::{Context, Result, bail};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct GitHubClient {
    client: reqwest::Client,
    token: String,
}

/// Cap on how long we'll sleep waiting for a rate-limit reset. Longer waits
/// would make `pin` / `update` appear hung from the user's perspective.
const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(60);

/// Delay before retrying a transient 5xx or network error.
const TRANSIENT_RETRY_DELAY: Duration = Duration::from_millis(500);

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

#[derive(Debug, Deserialize)]
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
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
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
            client: reqwest::Client::new(),
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

    /// Fetch the file tree for a repo at a given SHA.
    pub async fn fetch_tree(&self, owner: &str, repo: &str, sha: &str) -> Result<Vec<TreeEntry>> {
        let url =
            format!("https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1");
        let resp = self.get(&url).await?;
        let tree: Tree = resp.json().await.context("parsing tree")?;
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

        resp.text().await.context("reading file content")
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
