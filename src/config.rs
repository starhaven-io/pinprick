use crate::audit_patterns;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Fetch audited-actions list from pinprick.rs (default: false)
    #[serde(default)]
    pub fetch_remote: bool,

    /// Minimum severity to report: "low", "medium", or "high" (default: "low")
    #[serde(default = "default_severity")]
    pub severity: String,

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

#[derive(Debug, Default, Deserialize)]
pub struct IgnoreConfig {
    /// Skip audit for these actions entirely (e.g., "actions/checkout")
    #[serde(default)]
    pub actions: Vec<String>,

    /// Suppress findings whose description contains these strings
    #[serde(default)]
    pub patterns: Vec<String>,
}

fn default_severity() -> String {
    "low".to_string()
}

impl Config {
    /// Load config from global (~/.config/pinprick/config.toml) and per-repo (.pinprick.toml).
    /// Per-repo overrides global. Missing files are fine — defaults are used.
    pub fn load(repo_root: &Path) -> Self {
        let global = load_global();
        let local = load_local(repo_root);

        // Per-repo takes precedence; fall back to global; fall back to defaults
        match (global, local) {
            (_, Some(local)) => local,
            (Some(global), None) => global,
            (None, None) => Config::default(),
        }
    }

    /// Returns the minimum severity level as a numeric value for comparison.
    pub fn severity_threshold(&self) -> u8 {
        match self.severity.as_str() {
            "high" => 2,
            "medium" => 1,
            _ => 0, // "low" or anything else
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

    /// Check if an action should be skipped (ignored) during audit.
    pub fn is_action_ignored(&self, action_name: &str) -> bool {
        self.ignore
            .actions
            .iter()
            .any(|a| action_name.starts_with(a.as_str()))
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

fn load_global() -> Option<Config> {
    let home = std::env::var("HOME").ok()?;
    let path = Path::new(&home)
        .join(".config")
        .join("pinprick")
        .join("config.toml");
    load_file(&path)
}

fn load_local(repo_root: &Path) -> Option<Config> {
    load_file(&repo_root.join(".pinprick.toml"))
}

fn load_file(path: &Path) -> Option<Config> {
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
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
}
