use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const BUNDLED_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/bundled_audited_actions.json"));
const REMOTE_URL: &str = "https://pinprick.rs/audited-actions";

/// Minisign public key for the remote catalog, committed at the repo root and
/// embedded at compile time. The remote layer is fail-closed: without a valid
/// key in the build (or a valid signature on the fetched catalog), remote
/// entries are never honored — a compromised CDN must not be able to mark
/// malicious SHAs as audited.
const CATALOG_PUBKEY_FILE: &str = include_str!("../catalog-minisign.pub");

#[derive(Deserialize)]
struct AuditedEntry {
    #[serde(default)]
    action: Option<String>,
    sha: String,
    #[serde(default)]
    pinprick_version: Option<String>,
}

const LOCAL_CACHE_PINPRICK_VERSION: &str = env!("CARGO_PKG_VERSION");

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
/// Misses are silent — "not audited" just means the action is scanned via
/// GitHub. The exception is a remote catalog that fails signature
/// verification, which warns: that is either misconfigured serving
/// infrastructure or tampering, and should not pass unnoticed.
pub struct AuditedActions {
    bundled: HashMap<String, HashSet<String>>,
    cache_dir: Option<PathBuf>,
    /// Key used to verify remote catalog signatures. `None` (a build without
    /// a real public key) disables the remote layer entirely.
    catalog_key: Option<PublicKey>,
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
        let catalog_key = parse_catalog_key(CATALOG_PUBKEY_FILE);
        if fetch_remote && catalog_key.is_none() {
            eprintln!(
                "warning: remote audited-actions catalog disabled — this build carries no catalog public key"
            );
        }
        Self {
            bundled: load_bundled(),
            cache_dir: cache_dir(),
            catalog_key,
            client: crate::github::build_client(),
            fetch_remote,
            local: HashMap::new(),
            remote: HashMap::new(),
            remote_url: REMOTE_URL.to_string(),
        }
    }

    /// Check if an action at a specific SHA has been pre-audited. Returns
    /// which lookup layer satisfied the check, or `None` if no layer matched.
    pub async fn check(
        &mut self,
        owner: &str,
        repo: &str,
        subpath: Option<&str>,
        sha: &str,
    ) -> Option<AuditSource> {
        let key = action_key(owner, repo, subpath)?;

        if self
            .bundled
            .get(&key)
            .is_some_and(|shas| shas.contains(sha))
        {
            return Some(AuditSource::Bundled);
        }

        if !self.local.contains_key(&key) {
            let shas = self.load_local_cache(owner, repo, &key);
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
    pub fn cache_clean(
        &self,
        owner: &str,
        repo: &str,
        subpath: Option<&str>,
        sha: &str,
        tag: &str,
    ) {
        let Some(cache_dir) = &self.cache_dir else {
            return;
        };
        let Some(path) = cache_path(cache_dir, owner, repo) else {
            return;
        };
        let dir = cache_dir.join(owner);
        let Some(key) = action_key(owner, repo, subpath) else {
            return;
        };

        let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        // Drop entries written by other pinprick versions before the dedup
        // check. The reader (`parse_local_cache_entries`) already ignores them,
        // so without this a stale same-SHA entry would block the write — the
        // cache would never re-warm after an upgrade. Pruning here also keeps
        // the file from accumulating dead entries.
        entries.retain(|e| {
            e.get("pinprick_version").and_then(|v| v.as_str()) == Some(LOCAL_CACHE_PINPRICK_VERSION)
                && e.get("action").and_then(|v| v.as_str()).is_some()
        });

        if entries.iter().any(|e| {
            e.get("action").and_then(|v| v.as_str()) == Some(key.as_str())
                && e.get("sha").and_then(|s| s.as_str()) == Some(sha)
        }) {
            return;
        }

        entries.push(serde_json::json!({
            "action": key,
            "sha": sha,
            "tag": tag,
            "pinprick_version": LOCAL_CACHE_PINPRICK_VERSION
        }));

        if std::fs::create_dir_all(&dir).is_ok()
            && let Some(json) = render_entries(&entries)
        {
            let _ = std::fs::write(&path, json);
        }
    }

    fn load_local_cache(&self, owner: &str, repo: &str, key: &str) -> HashSet<String> {
        let Some(cache_dir) = &self.cache_dir else {
            return HashSet::new();
        };
        let Some(path) = cache_path(cache_dir, owner, repo) else {
            return HashSet::new();
        };
        let Ok(content) = std::fs::read_to_string(path) else {
            return HashSet::new();
        };
        parse_local_cache_entries(&content, key)
    }

    async fn fetch_remote_list(&self, action_key: &str) -> Option<HashSet<String>> {
        // No public key in this build → the remote layer stays dark.
        let key = self.catalog_key.as_ref()?;

        let url = format!("{}/{action_key}.json", self.remote_url);
        let bytes = self.fetch_url(&url).await?;

        // The signature is served next to the catalog file (minisign's `.minisig`
        // convention). A catalog without a valid signature is not honored — a
        // 404 on the catalog itself above is a normal miss, but a present
        // catalog with a missing or bad signature is worth a warning: it means
        // either serving infra is misconfigured or someone tampered with it.
        let sig_bytes = match self.fetch_url(&format!("{url}.minisig")).await {
            Some(b) => b,
            None => {
                eprintln!(
                    "warning: remote catalog for {action_key} has no signature — ignoring it"
                );
                return None;
            }
        };
        let sig_text = String::from_utf8_lossy(&sig_bytes);
        if !verify_catalog_signature(key, &bytes, &sig_text) {
            eprintln!(
                "warning: remote catalog for {action_key} failed signature verification — ignoring it"
            );
            return None;
        }

        Some(parse_entries(&String::from_utf8_lossy(&bytes)))
    }

    /// GET a URL and return the (size-capped) body, or `None` on any failure.
    async fn fetch_url(&self, url: &str) -> Option<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .header("User-Agent", "pinprick")
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        crate::github::read_capped(resp).await.ok()
    }
}

/// Parse the embedded `.pub` file into a verification key. Comment lines (and
/// the placeholder file, which is all comments) yield `None`.
fn parse_catalog_key(content: &str) -> Option<PublicKey> {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))?;
    PublicKey::from_base64(line).ok()
}

fn verify_catalog_signature(key: &PublicKey, data: &[u8], sig_text: &str) -> bool {
    match Signature::decode(sig_text) {
        // true: also accept legacy (non-prehashed) signatures.
        Ok(sig) => key.verify(data, &sig, true).is_ok(),
        Err(_) => false,
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

fn parse_local_cache_entries(json: &str, key: &str) -> HashSet<String> {
    let entries: Vec<AuditedEntry> = serde_json::from_str(json).unwrap_or_default();
    entries
        .into_iter()
        .filter(|e| e.pinprick_version.as_deref() == Some(LOCAL_CACHE_PINPRICK_VERSION))
        .filter(|e| e.action.as_deref() == Some(key))
        .map(|e| e.sha)
        .collect()
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

fn action_key(owner: &str, repo: &str, subpath: Option<&str>) -> Option<String> {
    if !is_safe_segment(owner) || !is_safe_segment(repo) {
        return None;
    }
    match subpath {
        Some(subpath) if is_safe_subpath(subpath) => Some(format!("{owner}/{repo}/{subpath}")),
        Some(_) => None,
        None => Some(format!("{owner}/{repo}")),
    }
}

fn is_safe_subpath(path: &str) -> bool {
    !path.is_empty() && path.split('/').all(is_safe_segment)
}

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
    fn action_key_rejects_unsafe_subpath_components() {
        assert_eq!(
            action_key("owner", "repo", Some("a/b.c")),
            Some("owner/repo/a/b.c".to_string())
        );

        for subpath in ["", ".", "..", "a//b", "a/../b", r"a\\b"] {
            assert_eq!(action_key("owner", "repo", Some(subpath)), None);
        }
        assert_eq!(action_key("owner/name", "repo", Some("a")), None);
        assert_eq!(action_key("owner", "repo/name", Some("a")), None);
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

    #[test]
    fn local_cache_ignores_unversioned_legacy_entries() {
        let rendered = r#"[
  { "sha": "aaa", "tag": "v1" }
]"#;
        assert!(parse_entries(rendered).contains("aaa"));
        assert!(!parse_local_cache_entries(rendered, "owner/repo").contains("aaa"));
    }

    #[test]
    fn local_cache_ignores_owner_repo_only_entries() {
        let rendered = serde_json::to_string(&vec![serde_json::json!({
            "sha": "aaa",
            "tag": "v1",
            "pinprick_version": LOCAL_CACHE_PINPRICK_VERSION
        })])
        .unwrap();
        assert!(!parse_local_cache_entries(&rendered, "owner/repo").contains("aaa"));
    }

    #[test]
    fn local_cache_accepts_current_version_entries() {
        let rendered = serde_json::to_string(&vec![serde_json::json!({
            "action": "owner/repo",
            "sha": "aaa",
            "tag": "v1",
            "pinprick_version": LOCAL_CACHE_PINPRICK_VERSION
        })])
        .unwrap();
        assert!(parse_local_cache_entries(&rendered, "owner/repo").contains("aaa"));
        assert!(!parse_local_cache_entries(&rendered, "owner/repo/subdir").contains("aaa"));
    }

    #[test]
    fn local_cache_separates_subpath_verdicts() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut aa = AuditedActions::new(false);
        aa.cache_dir = Some(dir.path().to_path_buf());

        aa.cache_clean("owner", "repo", Some("a"), "aaa", "v1");

        assert!(
            aa.load_local_cache("owner", "repo", "owner/repo/a")
                .contains("aaa")
        );
        assert!(
            !aa.load_local_cache("owner", "repo", "owner/repo/b")
                .contains("aaa")
        );

        aa.cache_clean("owner", "repo", Some("b"), "aaa", "v1");
        assert!(
            aa.load_local_cache("owner", "repo", "owner/repo/b")
                .contains("aaa")
        );

        let path = cache_path(dir.path(), "owner", "repo").unwrap();
        let on_disk: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(on_disk.len(), 2);
    }

    #[test]
    fn cache_clean_rewarms_after_version_change() {
        // A legacy entry (written by an older pinprick, no version field) must
        // not permanently block re-warming. The reader already ignores it, so
        // re-recording the same SHA has to replace it under the current version
        // rather than dedup-skipping — otherwise the cache never re-warms.
        let dir = tempfile::TempDir::new().unwrap();
        let mut aa = AuditedActions::new(false);
        aa.cache_dir = Some(dir.path().to_path_buf());

        let path = cache_path(dir.path(), "owner", "repo").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"[{ "sha": "aaa", "tag": "v1" }]"#).unwrap();
        // Pre-state: the legacy entry is invisible to the reader.
        assert!(
            !aa.load_local_cache("owner", "repo", "owner/repo")
                .contains("aaa")
        );

        aa.cache_clean("owner", "repo", None, "aaa", "v1");

        // The SHA is now cached under the current version…
        assert!(
            aa.load_local_cache("owner", "repo", "owner/repo")
                .contains("aaa")
        );
        // …and the stale legacy entry was pruned rather than duplicated.
        let on_disk: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk.len(), 1);
    }

    #[test]
    fn embedded_pubkey_parses() {
        // The committed catalog key must parse, or every release silently
        // ships with the remote layer disabled.
        assert!(parse_catalog_key(CATALOG_PUBKEY_FILE).is_some());
    }

    #[test]
    fn comment_only_pubkey_yields_no_key() {
        // A placeholder file (all comment lines) must not parse — it keeps
        // the remote layer disabled rather than panicking.
        assert!(parse_catalog_key("untrusted comment: nothing here\n").is_none());
        assert!(parse_catalog_key("").is_none());
    }

    #[test]
    fn real_pubkey_parses() {
        // The production catalog key in the format minisign writes —
        // exercises comment-stripping on a literal, independent of the
        // embedded file. (The minisign-verify docs key would also do, but
        // its base64 trips the typos linter.)
        let file = "untrusted comment: minisign public key\n\
                    RWRwyp1ae8MrgHSws68tQDd94KGWt1cqdTYZOEcIcPh+cQo9rWJIgC0x\n";
        assert!(parse_catalog_key(file).is_some());
    }

    mod remote {
        use super::*;
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Ephemeral signing identity for tests: the verification key (as
        /// parsed from a real `.pub` rendering) and a signer closure.
        fn test_identity() -> (PublicKey, impl Fn(&[u8]) -> String) {
            let minisign::KeyPair { pk, sk } =
                minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            let verify_key = parse_catalog_key(&pk.to_box().unwrap().to_string())
                .expect("generated public key must parse");
            let signer = move |data: &[u8]| {
                minisign::sign(None, &sk, std::io::Cursor::new(data), None, None)
                    .unwrap()
                    .to_string()
            };
            (verify_key, signer)
        }

        /// Mount a catalog body and its signature at `{key}.json[.minisig]`.
        async fn mount_signed(server: &MockServer, action_key: &str, body: &str, sig: &str) {
            Mock::given(method("GET"))
                .and(path(format!("/{action_key}.json")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(body.to_string(), "application/json"),
                )
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/{action_key}.json.minisig")))
                .respond_with(ResponseTemplate::new(200).set_body_string(sig.to_string()))
                .mount(server)
                .await;
        }

        #[tokio::test]
        async fn fetch_remote_list_parses_signed_entries() {
            let (key, sign) = test_identity();
            let body = serde_json::to_string(&json!([
                { "sha": "aaa", "tag": "v1" },
                { "sha": "bbb", "tag": "v2" }
            ]))
            .unwrap();

            let server = MockServer::start().await;
            mount_signed(&server, "actions/checkout", &body, &sign(body.as_bytes())).await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(key);
            aa.remote_url = server.uri();
            let shas = aa.fetch_remote_list("actions/checkout").await.unwrap();
            assert!(shas.contains("aaa"));
            assert!(shas.contains("bbb"));
        }

        #[tokio::test]
        async fn fetch_remote_list_non_success_is_none() {
            let (key, _) = test_identity();
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/actions/missing.json"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(key);
            aa.remote_url = server.uri();
            assert!(aa.fetch_remote_list("actions/missing").await.is_none());
        }

        #[tokio::test]
        async fn fetch_remote_list_missing_signature_is_none() {
            let (key, _) = test_identity();
            let body = serde_json::to_string(&json!([{ "sha": "aaa", "tag": "v1" }])).unwrap();

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/actions/unsigned.json"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
                .mount(&server)
                .await;
            // No .minisig mock → 404 on the signature.

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(key);
            aa.remote_url = server.uri();
            assert!(aa.fetch_remote_list("actions/unsigned").await.is_none());
        }

        #[tokio::test]
        async fn fetch_remote_list_tampered_body_is_none() {
            let (key, sign) = test_identity();
            let signed_body =
                serde_json::to_string(&json!([{ "sha": "aaa", "tag": "v1" }])).unwrap();
            let tampered_body =
                serde_json::to_string(&json!([{ "sha": "evil", "tag": "v1" }])).unwrap();

            let server = MockServer::start().await;
            // Signature is over the original body; the server returns a
            // different one — verification must reject it.
            mount_signed(
                &server,
                "actions/tampered",
                &tampered_body,
                &sign(signed_body.as_bytes()),
            )
            .await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(key);
            aa.remote_url = server.uri();
            assert!(aa.fetch_remote_list("actions/tampered").await.is_none());
        }

        #[tokio::test]
        async fn fetch_remote_list_wrong_key_is_none() {
            let (_, sign) = test_identity();
            let (other_key, _) = test_identity();
            let body = serde_json::to_string(&json!([{ "sha": "aaa", "tag": "v1" }])).unwrap();

            let server = MockServer::start().await;
            mount_signed(&server, "actions/wrongkey", &body, &sign(body.as_bytes())).await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(other_key);
            aa.remote_url = server.uri();
            assert!(aa.fetch_remote_list("actions/wrongkey").await.is_none());
        }

        #[tokio::test]
        async fn keyless_build_never_fetches() {
            // Even with a perfectly signed catalog available, a build without
            // a public key must not honor remote entries.
            let (_, sign) = test_identity();
            let body = serde_json::to_string(&json!([{ "sha": "aaa", "tag": "v1" }])).unwrap();

            let server = MockServer::start().await;
            mount_signed(&server, "actions/keyless", &body, &sign(body.as_bytes())).await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = None;
            aa.remote_url = server.uri();
            assert!(aa.fetch_remote_list("actions/keyless").await.is_none());
        }

        #[tokio::test]
        async fn check_falls_through_to_remote_layer() {
            let (key, sign) = test_identity();
            let body = serde_json::to_string(&json!([{ "sha": "feedface", "tag": "v3" }])).unwrap();

            let server = MockServer::start().await;
            mount_signed(&server, "some/action", &body, &sign(body.as_bytes())).await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(key);
            aa.remote_url = server.uri();
            aa.cache_dir = None; // don't consult the real ~/.cache during the test
            // Not bundled, no local cache hit → resolved by the remote layer.
            assert_eq!(
                aa.check("some", "action", None, "feedface").await,
                Some(AuditSource::Remote)
            );
            // A SHA the remote list doesn't contain stays unaudited.
            assert_eq!(aa.check("some", "action", None, "0000").await, None);
        }

        #[tokio::test]
        async fn check_uses_subpath_remote_identity() {
            let (key, sign) = test_identity();
            let body = serde_json::to_string(&json!([{ "sha": "feedface", "tag": "v3" }])).unwrap();

            let server = MockServer::start().await;
            mount_signed(&server, "some/action/a", &body, &sign(body.as_bytes())).await;

            let mut aa = AuditedActions::new(true);
            aa.catalog_key = Some(key);
            aa.remote_url = server.uri();
            aa.cache_dir = None;

            assert_eq!(
                aa.check("some", "action", Some("b"), "feedface").await,
                None
            );
            assert_eq!(
                aa.check("some", "action", Some("a"), "feedface").await,
                Some(AuditSource::Remote)
            );
        }
    }
}
