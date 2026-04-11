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
}

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
}
