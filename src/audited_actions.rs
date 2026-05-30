use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const BUNDLED_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/bundled_audited_actions.json"));
const REMOTE_URL: &str = "https://pinprick.rs/audited-actions";

#[derive(Deserialize)]
struct AuditedEntry {
    sha: String,
}

/// Which layer in the lookup satisfied an audited-action check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSource {
    /// Compiled into the pinprick binary from `audited-actions/`.
    Bundled,
    /// Read from `~/.cache/pinprick/audited/` (populated by previous scans).
    LocalCache,
    /// Fetched from `https://pinprick.rs/audited-actions/`.
    Remote,
}

impl AuditSource {
    /// Short human-readable label for terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::LocalCache => "local cache",
            Self::Remote => "pinprick.rs",
        }
    }
}

/// Layered lookup for pre-audited action SHAs.
///
/// Resolution order:
/// 1. **Bundled** — compiled into the binary from `audited-actions/`
/// 2. **Local cache** — `~/.cache/pinprick/audited/{owner}/{repo}.json`
/// 3. **Remote** — `https://pinprick.rs/audited-actions/{owner}/{repo}.json` (opt-in)
///
/// All failures are silent — a miss means "not audited, scan it via GitHub".
pub struct AuditedActions {
    bundled: HashMap<String, HashSet<String>>,
    cache_dir: Option<PathBuf>,
    client: reqwest::Client,
    fetch_remote: bool,
    local: HashMap<String, HashSet<String>>,
    remote: HashMap<String, HashSet<String>>,
    /// Remote catalog origin, [`REMOTE_URL`] in production. Only the in-module
    /// tests repoint it (at a local mock), so the production host is fixed.
    remote_url: String,
}

impl AuditedActions {
    pub fn new(fetch_remote: bool) -> Self {
        Self {
            bundled: load_bundled(),
            cache_dir: cache_dir(),
            client: crate::github::build_client(),
            fetch_remote,
            local: HashMap::new(),
            remote: HashMap::new(),
            remote_url: REMOTE_URL.to_string(),
        }
    }

    /// Check if an action at a specific SHA has been pre-audited. Returns
    /// which lookup layer satisfied the check, or `None` if no layer matched.
    pub async fn check(&mut self, owner: &str, repo: &str, sha: &str) -> Option<AuditSource> {
        let key = format!("{owner}/{repo}");

        if self
            .bundled
            .get(&key)
            .is_some_and(|shas| shas.contains(sha))
        {
            return Some(AuditSource::Bundled);
        }

        if !self.local.contains_key(&key) {
            let shas = self.load_local_cache(owner, repo);
            self.local.insert(key.clone(), shas);
        }
        if self.local.get(&key).is_some_and(|shas| shas.contains(sha)) {
            return Some(AuditSource::LocalCache);
        }

        if self.fetch_remote {
            if !self.remote.contains_key(&key) {
                let shas = self.fetch_remote_list(&key).await.unwrap_or_default();
                self.remote.insert(key.clone(), shas);
            }
            if self.remote.get(&key).is_some_and(|shas| shas.contains(sha)) {
                return Some(AuditSource::Remote);
            }
        }

        None
    }

    /// Record a clean scan result in the local cache.
    pub fn cache_clean(&self, owner: &str, repo: &str, sha: &str, tag: &str) {
        let Some(cache_dir) = &self.cache_dir else {
            return;
        };
        let Some(path) = cache_path(cache_dir, owner, repo) else {
            return;
        };
        let dir = cache_dir.join(owner);

        let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        if entries
            .iter()
            .any(|e| e.get("sha").and_then(|s| s.as_str()) == Some(sha))
        {
            return;
        }

        entries.push(serde_json::json!({ "sha": sha, "tag": tag }));

        if std::fs::create_dir_all(&dir).is_ok()
            && let Some(json) = render_entries(&entries)
        {
            let _ = std::fs::write(&path, json);
        }
    }

    fn load_local_cache(&self, owner: &str, repo: &str) -> HashSet<String> {
        let Some(cache_dir) = &self.cache_dir else {
            return HashSet::new();
        };
        let Some(path) = cache_path(cache_dir, owner, repo) else {
            return HashSet::new();
        };
        let Ok(content) = std::fs::read_to_string(path) else {
            return HashSet::new();
        };
        parse_entries(&content)
    }

    async fn fetch_remote_list(&self, action_key: &str) -> Option<HashSet<String>> {
        let url = format!("{}/{action_key}.json", self.remote_url);
        let resp = self
            .client
            .get(&url)
            .header("User-Agent", "pinprick")
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        let bytes = crate::github::read_capped(resp).await.ok()?;
        Some(parse_entries(&String::from_utf8_lossy(&bytes)))
    }
}

fn load_bundled() -> HashMap<String, HashSet<String>> {
    let map: HashMap<String, Vec<String>> = serde_json::from_str(BUNDLED_JSON).unwrap_or_default();
    map.into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect()
}

fn parse_entries(json: &str) -> HashSet<String> {
    let entries: Vec<AuditedEntry> = serde_json::from_str(json).unwrap_or_default();
    entries.into_iter().map(|e| e.sha).collect()
}

/// Serialize cache entries to their on-disk JSON form. Going through serde
/// (rather than hand-formatting strings) guarantees valid output even when a
/// `tag` contains quotes or backslashes — tags come from arbitrary `# comment`
/// text on a `uses:` line, so they can't be assumed escape-safe.
fn render_entries(entries: &[serde_json::Value]) -> Option<String> {
    serde_json::to_string_pretty(entries)
        .ok()
        .map(|s| format!("{s}\n"))
}

pub fn cache_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".cache/pinprick/audited"))
}

/// Build the on-disk cache path for an action, returning `None` if either
/// segment could escape the cache directory. `owner`/`repo` come from `uses:`
/// parsing and are well-formed in practice — this is defense in depth so a
/// crafted ref (`..`, an embedded separator) can't resolve outside the cache.
fn cache_path(cache_dir: &Path, owner: &str, repo: &str) -> Option<PathBuf> {
    (is_safe_segment(owner) && is_safe_segment(repo))
        .then(|| cache_dir.join(owner).join(format!("{repo}.json")))
}

/// A path segment is safe if it is non-empty, not a `.`/`..` traversal token,
/// and contains no path separator.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_segments_accepted() {
        for s in ["actions", "checkout", "setup-node", "a.b", "..foo", "v1"] {
            assert!(is_safe_segment(s), "{s} should be safe");
        }
    }

    #[test]
    fn unsafe_segments_rejected() {
        for s in ["", ".", "..", "a/b", "a\\b", "/etc", "..\\.."] {
            assert!(!is_safe_segment(s), "{s} should be rejected");
        }
    }

    #[test]
    fn cache_path_stays_inside_cache_dir() {
        let base = Path::new("/cache");
        assert_eq!(
            cache_path(base, "actions", "checkout"),
            Some(PathBuf::from("/cache/actions/checkout.json"))
        );
        // A traversal token or separator in either segment yields no path,
        // so the caller silently skips the cache rather than escaping it.
        assert_eq!(cache_path(base, "..", "checkout"), None);
        assert_eq!(cache_path(base, "actions", "../../etc/passwd"), None);
        assert_eq!(cache_path(base, "", "checkout"), None);
    }

    #[test]
    fn render_entries_round_trips() {
        let entries = vec![
            serde_json::json!({ "sha": "aaa", "tag": "v1" }),
            serde_json::json!({ "sha": "bbb", "tag": "v2" }),
        ];
        let rendered = render_entries(&entries).unwrap();
        assert!(rendered.ends_with('\n'));
        let shas = parse_entries(&rendered);
        assert!(shas.contains("aaa"));
        assert!(shas.contains("bbb"));
    }

    #[test]
    fn render_entries_escapes_adversarial_tag() {
        // A tag with quotes and a backslash would corrupt hand-formatted JSON.
        // serde escapes it, so the file stays valid and round-trips.
        let entries = vec![serde_json::json!({
            "sha": "abc123",
            "tag": r#"v1 "stable" \ release"#,
        })];
        let rendered = render_entries(&entries).unwrap();
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&rendered).expect("rendered cache must be valid JSON");
        assert_eq!(parsed[0]["sha"], "abc123");
        assert_eq!(parsed[0]["tag"], r#"v1 "stable" \ release"#);
        // The reader still recovers the sha.
        assert!(parse_entries(&rendered).contains("abc123"));
    }

    mod remote {
        use super::*;
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[tokio::test]
        async fn fetch_remote_list_parses_entries() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/actions/checkout.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "sha": "aaa", "tag": "v1" },
                    { "sha": "bbb", "tag": "v2" }
                ])))
                .mount(&server)
                .await;

            let mut aa = AuditedActions::new(true);
            aa.remote_url = server.uri();
            let shas = aa.fetch_remote_list("actions/checkout").await.unwrap();
            assert!(shas.contains("aaa"));
            assert!(shas.contains("bbb"));
        }

        #[tokio::test]
        async fn fetch_remote_list_non_success_is_none() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/actions/missing.json"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            let mut aa = AuditedActions::new(true);
            aa.remote_url = server.uri();
            assert!(aa.fetch_remote_list("actions/missing").await.is_none());
        }

        #[tokio::test]
        async fn check_falls_through_to_remote_layer() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/some/action.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "sha": "feedface", "tag": "v3" }
                ])))
                .mount(&server)
                .await;

            let mut aa = AuditedActions::new(true);
            aa.remote_url = server.uri();
            aa.cache_dir = None; // don't consult the real ~/.cache during the test
            // Not bundled, no local cache hit → resolved by the remote layer.
            assert_eq!(
                aa.check("some", "action", "feedface").await,
                Some(AuditSource::Remote)
            );
            // A SHA the remote list doesn't contain stays unaudited.
            assert_eq!(aa.check("some", "action", "0000").await, None);
        }
    }
}
