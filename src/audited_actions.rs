use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const BUNDLED_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/bundled_audited_actions.json"));
const REMOTE_URL: &str = "https://pinprick.rs/audited-actions";

#[derive(Deserialize)]
struct AuditedEntry {
    sha: String,
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
}

impl AuditedActions {
    pub fn new(fetch_remote: bool) -> Self {
        Self {
            bundled: load_bundled(),
            cache_dir: cache_dir(),
            client: reqwest::Client::new(),
            fetch_remote,
            local: HashMap::new(),
            remote: HashMap::new(),
        }
    }

    /// Check if an action at a specific SHA has been pre-audited.
    pub async fn check(&mut self, owner: &str, repo: &str, sha: &str) -> bool {
        let key = format!("{owner}/{repo}");

        if self
            .bundled
            .get(&key)
            .is_some_and(|shas| shas.contains(sha))
        {
            return true;
        }

        if !self.local.contains_key(&key) {
            let shas = self.load_local_cache(&key);
            self.local.insert(key.clone(), shas);
        }
        if self.local.get(&key).is_some_and(|shas| shas.contains(sha)) {
            return true;
        }

        if self.fetch_remote {
            if !self.remote.contains_key(&key) {
                let shas = self.fetch_remote_list(&key).await.unwrap_or_default();
                self.remote.insert(key.clone(), shas);
            }
            if self.remote.get(&key).is_some_and(|shas| shas.contains(sha)) {
                return true;
            }
        }

        false
    }

    /// Record a clean scan result in the local cache.
    pub fn cache_clean(&self, owner: &str, repo: &str, sha: &str, tag: &str) {
        let Some(cache_dir) = &self.cache_dir else {
            return;
        };

        let dir = cache_dir.join(owner);
        let path = dir.join(format!("{repo}.json"));

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

        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = std::fs::write(
                &path,
                serde_json::to_string_pretty(&entries).unwrap_or_default(),
            );
        }
    }

    fn load_local_cache(&self, action_key: &str) -> HashSet<String> {
        let Some(cache_dir) = &self.cache_dir else {
            return HashSet::new();
        };
        let path = cache_dir.join(format!("{action_key}.json"));
        let Ok(content) = std::fs::read_to_string(path) else {
            return HashSet::new();
        };
        parse_entries(&content)
    }

    async fn fetch_remote_list(&self, action_key: &str) -> Option<HashSet<String>> {
        let url = format!("{REMOTE_URL}/{action_key}.json");
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

        let text = resp.text().await.ok()?;
        Some(parse_entries(&text))
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

fn cache_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".cache/pinprick/audited"))
}
