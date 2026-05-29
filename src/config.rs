use crate::audit_patterns;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Fetch audited-actions list from pinprick.rs (default: false)
    #[serde(default)]
    pub fetch_remote: bool,

    /// Minimum severity to report (default: low). An unrecognized value is a
    /// parse error, surfaced as a warning — not silently treated as "low".
    #[serde(default)]
    pub severity: SeverityFilter,

    /// Finding suppression rules
    #[serde(default)]
    pub ignore: IgnoreConfig,

    /// Additional file extensions (beyond the built-in set) to treat as
    /// data formats when evaluating unversioned-URL fetches. Case-insensitive;
    /// leading dots are stripped.
    #[serde(default)]
    pub extra_data_formats: Vec<String>,

    /// Hostnames that are trusted sources for unversioned fetches. A fetch
    /// whose URL host exactly matches an entry is downgraded from a finding
    /// to an allowed match. Case-insensitive. Only applies to the
    /// unversioned-URL rules — `/latest/` URLs and pipe-to-shell still fire
    /// regardless.
    #[serde(default)]
    pub trusted_hosts: Vec<String>,

    /// Additional GitHub owners (users or orgs) whose actions are considered
    /// trusted publishers for the `source.unverified` scoring rule. Appended
    /// to the built-in baseline (`actions`, `github`). Case-insensitive.
    #[serde(default)]
    pub trusted_owners: Vec<String>,
}

/// Baseline list of trusted action publishers. GitHub's own orgs are
/// always considered trusted; users extend this list via `trusted-owners`
/// in `.pinprick.toml`.
const BASELINE_TRUSTED_OWNERS: &[&str] = &["actions", "github"];

/// Minimum severity threshold for reporting, set via `severity` in
/// `.pinprick.toml`. Deserializing rejects unknown values so a typo can't
/// silently widen or narrow what gets reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityFilter {
    #[default]
    Low,
    Medium,
    High,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreConfig {
    /// Skip audit for these actions entirely (e.g., "actions/checkout")
    #[serde(default)]
    pub actions: Vec<String>,

    /// Suppress findings whose description contains these strings
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl Config {
    /// Load config from global (~/.config/pinprick/config.toml) and per-repo (.pinprick.toml).
    /// Per-repo overrides global. Missing files are fine — defaults are used.
    pub fn load(repo_root: &Path) -> Self {
        // Per-repo takes precedence. A malformed per-repo file falls back to
        // DEFAULTS, not the global config: the author meant to configure THIS
        // repo, so silently substituting an unrelated global policy is more
        // surprising than using documented defaults. Global is consulted only
        // when there is no per-repo file at all.
        match load_local(repo_root) {
            ConfigLoad::Loaded(local) => local,
            ConfigLoad::Malformed => Config::default(),
            ConfigLoad::Absent => match load_global() {
                ConfigLoad::Loaded(global) => global,
                ConfigLoad::Malformed | ConfigLoad::Absent => Config::default(),
            },
        }
    }

    /// Returns the minimum severity level as a numeric value for comparison.
    pub fn severity_threshold(&self) -> u8 {
        match self.severity {
            SeverityFilter::High => 2,
            SeverityFilter::Medium => 1,
            SeverityFilter::Low => 0,
        }
    }

    /// Check if a finding severity meets the configured threshold.
    pub fn meets_severity(&self, severity: &str) -> bool {
        let level = match severity {
            "high" => 2,
            "medium" => 1,
            _ => 0,
        };
        level >= self.severity_threshold()
    }

    /// Check if an action should be skipped (ignored) during audit. A pattern
    /// matches when it equals the `owner/repo` exactly or names a prefix at a
    /// path boundary, so `actions` (or `actions/`) ignores the whole org while
    /// `actions/check` does not silently swallow `actions/checkout`.
    pub fn is_action_ignored(&self, action_name: &str) -> bool {
        self.ignore
            .actions
            .iter()
            .any(|pattern| ignore_pattern_matches(pattern, action_name))
    }

    /// Check if a finding should be suppressed based on its description.
    pub fn is_pattern_ignored(&self, description: &str) -> bool {
        self.ignore
            .patterns
            .iter()
            .any(|p| description.contains(p.as_str()))
    }

    /// Check if a URL is exempt from unversioned-fetch rules because its
    /// path ends in a known data-format extension. Consults both the
    /// built-in set and the user-configured `extra_data_formats` list.
    pub fn is_data_format_exempt(&self, url: &str) -> bool {
        if audit_patterns::url_is_data_format(url) {
            return true;
        }
        let Some(ext) = audit_patterns::url_extension(url) else {
            return false;
        };
        self.extra_data_formats
            .iter()
            .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(ext))
    }

    /// Check if a URL's host is in the configured `trusted_hosts` list.
    /// Case-insensitive exact match. Returns false if the URL cannot be
    /// parsed or has no host.
    pub fn is_host_trusted(&self, url: &str) -> bool {
        let Some(host) = audit_patterns::url_host(url) else {
            return false;
        };
        self.trusted_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    /// Check if an action publisher (owner) is trusted. Combines the
    /// built-in baseline (`actions`, `github`) with the user-configured
    /// `trusted_owners` list. Case-insensitive.
    pub fn is_owner_trusted(&self, owner: &str) -> bool {
        BASELINE_TRUSTED_OWNERS
            .iter()
            .any(|b| b.eq_ignore_ascii_case(owner))
            || self
                .trusted_owners
                .iter()
                .any(|o| o.eq_ignore_ascii_case(owner))
    }
}

/// True if an `ignore.actions` pattern matches an action's `owner/repo` at a
/// path boundary. A trailing slash on the pattern is ignored (`actions` and
/// `actions/` behave identically); an empty pattern matches nothing.
fn ignore_pattern_matches(pattern: &str, action_name: &str) -> bool {
    let pattern = pattern.trim_end_matches('/');
    if pattern.is_empty() {
        return false;
    }
    // GitHub owner/repo slugs are case-insensitive, and every sibling matcher
    // (trusted-hosts, trusted-owners, data formats) ignores case — so this one
    // must too, or an ignore entry silently fails to match a differently-cased
    // `uses:` line.
    let pattern = pattern.to_ascii_lowercase();
    let action_name = action_name.to_ascii_lowercase();
    action_name == pattern || action_name.starts_with(&format!("{pattern}/"))
}

/// Outcome of attempting to load a config file: present and valid, present but
/// unparsable, or absent. The caller distinguishes `Malformed` from `Absent`
/// because a malformed per-repo file must fall back to defaults, not inherit
/// the global config.
enum ConfigLoad {
    Loaded(Config),
    Malformed,
    Absent,
}

fn load_global() -> ConfigLoad {
    let Ok(home) = std::env::var("HOME") else {
        return ConfigLoad::Absent;
    };
    let path = Path::new(&home)
        .join(".config")
        .join("pinprick")
        .join("config.toml");
    load_file(&path)
}

fn load_local(repo_root: &Path) -> ConfigLoad {
    load_file(&repo_root.join(".pinprick.toml"))
}

/// Load and parse a config file. A missing or unreadable file is `Absent`
/// (defaults apply, silently — no config is the normal case). A file that
/// exists but fails to parse is `Malformed`, and warns to stderr first: a
/// silently-dropped config would leave the user thinking their `ignore` /
/// `severity` / `trusted-*` rules are active when they aren't.
fn load_file(path: &Path) -> ConfigLoad {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return ConfigLoad::Absent,
    };
    match toml::from_str(&content) {
        Ok(config) => ConfigLoad::Loaded(config),
        Err(e) => {
            eprintln!(
                "warning: failed to parse {}, using defaults:\n{e}",
                path.display()
            );
            ConfigLoad::Malformed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_data_format_exempt_built_in() {
        let cfg = Config::default();
        assert!(cfg.is_data_format_exempt("https://example.com/data.json"));
        assert!(cfg.is_data_format_exempt("https://example.com/config.yaml"));
    }

    #[test]
    fn is_data_format_exempt_rejects_non_data_default() {
        let cfg = Config::default();
        assert!(!cfg.is_data_format_exempt("https://example.com/tool.tar.gz"));
        assert!(!cfg.is_data_format_exempt("https://example.com/install.sh"));
    }

    #[test]
    fn is_data_format_exempt_with_extra_format() {
        let cfg = Config {
            extra_data_formats: vec!["proto".to_string(), "graphql".to_string()],
            ..Config::default()
        };
        assert!(cfg.is_data_format_exempt("https://example.com/api.proto"));
        assert!(cfg.is_data_format_exempt("https://example.com/schema.graphql"));
        assert!(!cfg.is_data_format_exempt("https://example.com/install.sh"));
    }

    #[test]
    fn is_data_format_exempt_extra_format_case_insensitive() {
        let cfg = Config {
            extra_data_formats: vec!["proto".to_string()],
            ..Config::default()
        };
        assert!(cfg.is_data_format_exempt("https://example.com/API.PROTO"));
    }

    #[test]
    fn is_data_format_exempt_strips_leading_dot_in_config() {
        let cfg = Config {
            extra_data_formats: vec![".proto".to_string()],
            ..Config::default()
        };
        assert!(cfg.is_data_format_exempt("https://example.com/api.proto"));
    }

    #[test]
    fn is_data_format_exempt_does_not_match_similar_extension() {
        let cfg = Config {
            extra_data_formats: vec!["proto".to_string()],
            ..Config::default()
        };
        assert!(!cfg.is_data_format_exempt("https://example.com/api.protobuf"));
    }

    #[test]
    fn deserializes_extra_data_formats_from_toml() {
        let toml_content = r#"
extra-data-formats = ["proto", "graphql"]
"#;
        let cfg: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(cfg.extra_data_formats, vec!["proto", "graphql"]);
    }

    #[test]
    fn missing_extra_data_formats_defaults_to_empty() {
        let toml_content = "";
        let cfg: Config = toml::from_str(toml_content).unwrap();
        assert!(cfg.extra_data_formats.is_empty());
    }

    #[test]
    fn is_host_trusted_exact_match() {
        let cfg = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        assert!(cfg.is_host_trusted("https://artifacts.example.com/foo/bar"));
    }

    #[test]
    fn is_host_trusted_case_insensitive() {
        let cfg = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        assert!(cfg.is_host_trusted("https://ARTIFACTS.EXAMPLE.COM/foo"));
    }

    #[test]
    fn is_host_trusted_strips_port() {
        let cfg = Config {
            trusted_hosts: vec!["artifacts.example.com".to_string()],
            ..Config::default()
        };
        assert!(cfg.is_host_trusted("https://artifacts.example.com:8443/foo"));
    }

    #[test]
    fn is_host_trusted_no_subdomain_match() {
        let cfg = Config {
            trusted_hosts: vec!["example.com".to_string()],
            ..Config::default()
        };
        // Exact match only — `api.example.com` is not trusted.
        assert!(!cfg.is_host_trusted("https://api.example.com/foo"));
    }

    #[test]
    fn is_host_trusted_empty_list_rejects_all() {
        let cfg = Config::default();
        assert!(!cfg.is_host_trusted("https://example.com/foo"));
    }

    #[test]
    fn is_host_trusted_non_url_returns_false() {
        let cfg = Config {
            trusted_hosts: vec!["example.com".to_string()],
            ..Config::default()
        };
        assert!(!cfg.is_host_trusted("example.com"));
    }

    #[test]
    fn deserializes_trusted_hosts_from_toml() {
        let toml_content = r#"
trusted-hosts = ["artifacts.example.com", "releases.example.org"]
"#;
        let cfg: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(
            cfg.trusted_hosts,
            vec!["artifacts.example.com", "releases.example.org"]
        );
    }

    #[test]
    fn missing_trusted_hosts_defaults_to_empty() {
        let toml_content = "";
        let cfg: Config = toml::from_str(toml_content).unwrap();
        assert!(cfg.trusted_hosts.is_empty());
    }

    // ── severity validation ────────────────────────────────────────────

    #[test]
    fn severity_valid_values_parse() {
        for (value, expected) in [
            ("low", SeverityFilter::Low),
            ("medium", SeverityFilter::Medium),
            ("high", SeverityFilter::High),
        ] {
            let cfg: Config = toml::from_str(&format!("severity = \"{value}\"")).unwrap();
            assert_eq!(cfg.severity, expected);
        }
    }

    #[test]
    fn severity_invalid_value_is_error() {
        // A typo must fail loudly, not silently fall back to the most
        // permissive threshold.
        assert!(toml::from_str::<Config>("severity = \"higq\"").is_err());
        assert!(toml::from_str::<Config>("severity = \"critical\"").is_err());
    }

    #[test]
    fn default_severity_is_low() {
        let cfg = Config::default();
        assert_eq!(cfg.severity, SeverityFilter::Low);
        assert_eq!(cfg.severity_threshold(), 0);
    }

    #[test]
    fn severity_threshold_and_meets() {
        let high = Config {
            severity: SeverityFilter::High,
            ..Config::default()
        };
        assert_eq!(high.severity_threshold(), 2);
        assert!(high.meets_severity("high"));
        assert!(!high.meets_severity("medium"));
        assert!(!high.meets_severity("low"));

        let low = Config::default();
        assert!(low.meets_severity("low"));
        assert!(low.meets_severity("high"));
    }

    // ── unknown keys ───────────────────────────────────────────────────

    #[test]
    fn unknown_top_level_key_is_error() {
        // A misspelled key (e.g. `trusted-onwers`) must be rejected rather
        // than silently ignored, so the user notices the rule isn't applied.
        assert!(toml::from_str::<Config>("trusted-onwers = [\"acme\"]").is_err());
        assert!(toml::from_str::<Config>("definitely-not-a-key = true").is_err());
    }

    #[test]
    fn unknown_nested_ignore_key_is_error() {
        assert!(toml::from_str::<Config>("[ignore]\nbogus = 1").is_err());
    }

    // ── load_file: warn vs silent ──────────────────────────────────────

    #[test]
    fn load_file_missing_is_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        // No file written — absent config is silent, defaults apply.
        assert!(matches!(
            load_file(&dir.path().join("config.toml")),
            ConfigLoad::Absent
        ));
    }

    #[test]
    fn load_file_malformed_is_distinct_from_absent() {
        // Present-but-unparsable is `Malformed` (warning goes to stderr), NOT
        // `Absent` — so a bad per-repo file falls back to defaults, not global.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "severity = \"nope\"\n").unwrap();
        assert!(matches!(load_file(&path), ConfigLoad::Malformed));
    }

    #[test]
    fn load_file_valid_is_parsed() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "severity = \"high\"\nfetch-remote = true\n").unwrap();
        let ConfigLoad::Loaded(cfg) = load_file(&path) else {
            panic!("valid config should parse");
        };
        assert_eq!(cfg.severity, SeverityFilter::High);
        assert!(cfg.fetch_remote);
    }

    #[test]
    fn ignore_pattern_is_case_insensitive() {
        // GitHub slugs are case-insensitive, so an ignore entry must match
        // regardless of the casing used on the `uses:` line.
        assert!(ignore_pattern_matches(
            "actions/checkout",
            "Actions/Checkout"
        ));
        assert!(ignore_pattern_matches("Actions", "actions/setup-node"));
    }

    // ── ignore.actions matching ────────────────────────────────────────

    #[test]
    fn ignore_pattern_exact_and_org_prefix() {
        assert!(ignore_pattern_matches(
            "actions/checkout",
            "actions/checkout"
        ));
        // A bare owner ignores the whole org…
        assert!(ignore_pattern_matches("actions", "actions/checkout"));
        // …and a trailing slash behaves the same.
        assert!(ignore_pattern_matches("actions/", "actions/setup-node"));
    }

    #[test]
    fn ignore_pattern_respects_path_boundary() {
        // The footgun: a partial name must not swallow a longer one.
        assert!(!ignore_pattern_matches("actions/check", "actions/checkout"));
        assert!(!ignore_pattern_matches(
            "aws",
            "aws-actions/configure-aws-credentials"
        ));
        assert!(!ignore_pattern_matches(
            "actions/checkout",
            "actions/checkout-action"
        ));
    }

    #[test]
    fn ignore_pattern_empty_matches_nothing() {
        assert!(!ignore_pattern_matches("", "actions/checkout"));
        assert!(!ignore_pattern_matches("/", "actions/checkout"));
    }

    #[test]
    fn is_action_ignored_through_config() {
        let cfg = Config {
            ignore: IgnoreConfig {
                actions: vec!["actions/checkout".to_string(), "aws-actions".to_string()],
                patterns: vec![],
            },
            ..Config::default()
        };
        assert!(cfg.is_action_ignored("actions/checkout"));
        assert!(cfg.is_action_ignored("aws-actions/configure-aws-credentials"));
        assert!(!cfg.is_action_ignored("actions/setup-node"));
        assert!(!cfg.is_action_ignored("actions/checkout-action"));
    }
}
