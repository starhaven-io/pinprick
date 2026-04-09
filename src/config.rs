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
