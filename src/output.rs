use colored::Colorize;
use serde::Serialize;

use crate::audit_patterns::Severity;

// ── Pin output ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PinResult {
    pub file: String,
    pub action: String,
    pub old_ref: String,
    pub sha: String,
    pub tag: String,
    pub line: usize,
}

#[derive(Serialize)]
pub struct PinSkip {
    pub file: String,
    pub action: String,
    pub reason: String,
    pub line: usize,
}

#[derive(Serialize)]
pub struct PinReport {
    pub pinned: Vec<PinResult>,
    pub skipped: Vec<PinSkip>,
    pub applied: bool,
}

impl PinReport {
    pub fn print_human(&self) {
        let mut current_file = String::new();

        for p in &self.pinned {
            if p.file != current_file {
                if !current_file.is_empty() {
                    println!();
                }
                println!("{}", p.file.bold());
                current_file.clone_from(&p.file);
            }
            println!(
                "  {} {} {} {}",
                p.action.cyan(),
                format!("@{}", p.old_ref).dimmed(),
                "->".dimmed(),
                format!("@{}… # {}", &p.sha[..12], p.tag).green()
            );
        }

        for s in &self.skipped {
            if s.file != current_file {
                if !current_file.is_empty() {
                    println!();
                }
                println!("{}", s.file.bold());
                current_file.clone_from(&s.file);
            }
            println!(
                "  {} {}",
                format!("! {}", s.action).yellow(),
                format!("-- {}", s.reason).dimmed()
            );
        }

        if !self.pinned.is_empty() || !self.skipped.is_empty() {
            println!();
        }

        let total_files: std::collections::HashSet<&str> =
            self.pinned.iter().map(|p| p.file.as_str()).collect();
        let verb = if self.applied { "Pinned" } else { "Would pin" };
        println!(
            "{verb} {} action{} across {} file{}{}",
            self.pinned.len(),
            if self.pinned.len() == 1 { "" } else { "s" },
            total_files.len(),
            if total_files.len() == 1 { "" } else { "s" },
            if self.skipped.is_empty() {
                String::new()
            } else {
                format!(" ({} skipped)", self.skipped.len())
            }
        );
        if !self.applied && !self.pinned.is_empty() {
            println!("Run with {} to apply.", "--write".bold());
        }
    }

    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }
}

// ── Update output ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct UpdateResult {
    pub file: String,
    pub action: String,
    pub current_tag: String,
    pub current_sha: String,
    pub latest_tag: String,
    pub latest_sha: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_url: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateReport {
    pub updates: Vec<UpdateResult>,
    pub up_to_date: usize,
    pub applied: bool,
}

impl UpdateReport {
    pub fn print_human(&self) {
        if self.updates.is_empty() {
            println!("All pinned actions are up to date.");
            return;
        }

        let mut current_file = String::new();
        for u in &self.updates {
            if u.file != current_file {
                if !current_file.is_empty() {
                    println!();
                }
                println!("{}", u.file.bold());
                current_file.clone_from(&u.file);
            }
            println!(
                "  {} {} {} {}",
                u.action.cyan(),
                u.current_tag.dimmed(),
                "->".dimmed(),
                u.latest_tag.green()
            );
            if let Some(url) = &u.release_url {
                println!("    {}", url.dimmed());
            }
        }

        println!();
        if self.applied {
            println!(
                "{} update{} applied.",
                self.updates.len(),
                if self.updates.len() == 1 { "" } else { "s" }
            );
        } else {
            println!(
                "{} update{} available. Run with {} to apply.",
                self.updates.len(),
                if self.updates.len() == 1 { "" } else { "s" },
                "--write".bold()
            );
        }
    }

    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }
}

// ── Audit output ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AuditFinding {
    pub severity: String,
    pub category: String,
    pub action: String,
    pub source_file: String,
    pub line: Option<usize>,
    pub pattern_matched: String,
    pub description: String,
    /// When this finding came from scanning a remote action's source,
    /// the workflow file in the scanning repo that loaded the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_file: Option<String>,
    /// 1-based line number of the `uses:` line in `workflow_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_line: Option<usize>,
}

#[derive(Serialize)]
pub struct AuditMatch {
    pub severity: String,
    pub category: String,
    pub action: String,
    pub source_file: String,
    pub line: Option<usize>,
    pub pattern_matched: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct AuditReport {
    pub findings: Vec<AuditFinding>,
    pub allowed: Vec<AuditMatch>,
    pub actions_scanned: usize,
    pub had_token: bool,
    /// Number of actions whose SHA matched the bundled list.
    #[serde(default)]
    pub audited_bundled: usize,
    /// Number of actions whose SHA matched the local cache.
    #[serde(default)]
    pub audited_local_cache: usize,
    /// Number of actions whose SHA matched the remote pinprick.rs list.
    #[serde(default)]
    pub audited_remote: usize,
    /// Number of SHA- or tag-pinned actions that were fetched and scanned
    /// fresh (not in any audited-actions list).
    #[serde(default)]
    pub scanned_fresh: usize,
    /// Number of branch refs (`@main`) that were scanned at current tip.
    /// Not a durable audit — the content can change on the next fetch,
    /// and `pinprick pin` cannot auto-resolve these.
    #[serde(default)]
    pub scanned_unpinned_branch: usize,
    /// Number of sliding tags (`@v4`) that were scanned at current tip.
    /// Not a durable audit — the tag can be retargeted, but `pinprick pin`
    /// can resolve these to exact SHAs.
    #[serde(default)]
    pub scanned_unpinned_sliding: usize,
    /// Number of actions skipped by `ignore.actions` in the config.
    #[serde(default)]
    pub ignored: usize,
}

impl AuditReport {
    pub fn print_human(&self, verbose: bool) {
        for f in &self.findings {
            let sev = match f.severity.as_str() {
                "high" => "HIGH".red().bold(),
                "medium" => "MEDIUM".yellow().bold(),
                _ => "LOW".dimmed(),
            };

            let location = match f.line {
                Some(n) => format!("{}:{n}", f.source_file),
                None => f.source_file.clone(),
            };

            println!("{sev}  {}", location.bold());
            if !f.action.is_empty() {
                println!("      action: {}", f.action.cyan());
            }
            println!("      {}", f.pattern_matched.dimmed());
            println!("      {}", f.description);
            println!();
        }

        if verbose && !self.allowed.is_empty() {
            println!("{}", "Allowed (matched but passed check):".dimmed());
            for m in &self.allowed {
                let location = match m.line {
                    Some(n) => format!("{}:{n}", m.source_file),
                    None => m.source_file.clone(),
                };
                println!("{}   {}", "OK".green().bold(), location.bold());
                if !m.action.is_empty() {
                    println!("      action: {}", m.action.cyan());
                }
                println!("      {}", m.pattern_matched.dimmed());
                println!("      reason: {}", m.reason.dimmed());
                println!();
            }
        }

        if self.findings.is_empty() {
            println!("No runtime fetch risks found.");
        } else {
            let high = self
                .findings
                .iter()
                .filter(|f| f.severity == "high")
                .count();
            let med = self
                .findings
                .iter()
                .filter(|f| f.severity == "medium")
                .count();
            let low = self.findings.iter().filter(|f| f.severity == "low").count();

            println!(
                "{} finding{} ({} high, {} medium, {} low)",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                high,
                med,
                low
            );
        }

        for line in self.audit_summary_lines() {
            println!("{line}");
        }

        if verbose && !self.allowed.is_empty() {
            println!(
                "{} allowed match{}",
                self.allowed.len(),
                if self.allowed.len() == 1 { "" } else { "es" }
            );
        }

        if !self.had_token {
            println!(
                "{}",
                "Note: no GitHub token — action source code was not scanned.".dimmed()
            );
        }
    }

    /// Build the summary of how actions were audited. Up to four lines,
    /// each omitted when its count is zero:
    ///
    /// 1. `Audited N actions: X bundled, Y local cache, Z pinprick.rs, W scanned fresh.`
    /// 2. `N sliding tags scanned. Run `pinprick pin` to resolve.`
    /// 3. `M branch refs scanned. Pin to a SHA manually.`
    /// 4. `K actions ignored per config.`
    fn audit_summary_lines(&self) -> Vec<String> {
        let trusted_total = self.audited_bundled
            + self.audited_local_cache
            + self.audited_remote
            + self.scanned_fresh;
        let unpinned_total = self.scanned_unpinned_branch + self.scanned_unpinned_sliding;
        if trusted_total == 0 && unpinned_total == 0 && self.ignored == 0 {
            return Vec::new();
        }

        let mut lines = Vec::new();

        if trusted_total > 0 {
            let mut parts: Vec<String> = Vec::new();
            if self.audited_bundled > 0 {
                parts.push(format!("{} bundled", self.audited_bundled));
            }
            if self.audited_local_cache > 0 {
                parts.push(format!("{} local cache", self.audited_local_cache));
            }
            if self.audited_remote > 0 {
                parts.push(format!("{} pinprick.rs", self.audited_remote));
            }
            if self.scanned_fresh > 0 {
                parts.push(
                    format!("{} scanned fresh", self.scanned_fresh)
                        .blue()
                        .to_string(),
                );
            }
            lines.push(format!(
                "{} {} action{}: {}.",
                "Audited".green(),
                trusted_total,
                if trusted_total == 1 { "" } else { "s" },
                parts.join(", ")
            ));
        }

        if self.scanned_unpinned_sliding > 0 {
            lines.push(
                format!(
                    "{} sliding tag{} scanned. Run `pinprick pin` to resolve.",
                    self.scanned_unpinned_sliding,
                    if self.scanned_unpinned_sliding == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
                .yellow()
                .to_string(),
            );
        }

        if self.scanned_unpinned_branch > 0 {
            lines.push(
                format!(
                    "{} branch ref{} scanned. Pin to a SHA manually.",
                    self.scanned_unpinned_branch,
                    if self.scanned_unpinned_branch == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
                .yellow()
                .to_string(),
            );
        }

        if self.ignored > 0 {
            lines.push(
                format!(
                    "{} action{} ignored per config.",
                    self.ignored,
                    if self.ignored == 1 { "" } else { "s" }
                )
                .dimmed()
                .to_string(),
            );
        }
        lines
    }

    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }

    /// Emit findings as a SARIF 2.1.0 document suitable for
    /// `github/codeql-action/upload-sarif`.
    ///
    /// Local findings (from workflow `run:` blocks) anchor to their
    /// workflow file + line. Remote findings (from scanning an action's
    /// own source code) anchor to the `uses:` line in the workflow that
    /// loaded the action, with the original remote path surfaced in the
    /// result message — the remote file doesn't exist in the scanning
    /// repo, so it cannot be a physical location itself.
    pub fn print_sarif(&self) {
        println!(
            "{}",
            serde_json::to_string_pretty(&self.build_sarif()).unwrap()
        );
    }

    fn build_sarif(&self) -> SarifDocument {
        let results = self
            .findings
            .iter()
            .map(|f| {
                let (uri, start_line) =
                    if let (Some(wf), Some(wl)) = (f.workflow_file.as_ref(), f.workflow_line) {
                        (wf.clone(), wl)
                    } else {
                        (f.source_file.clone(), f.line.unwrap_or(1))
                    };

                let mut text = f.description.clone();
                if f.workflow_file.is_some() {
                    text.push_str(&format!(" (in {})", f.source_file));
                }

                SarifResult {
                    rule_id: format!("pinprick/{}", f.category),
                    level: sarif_level(&f.severity).to_string(),
                    message: SarifText { text },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation { uri },
                            region: SarifRegion {
                                start_line: start_line.max(1),
                            },
                        },
                    }],
                }
            })
            .collect();

        let rules = SARIF_RULES
            .iter()
            .map(|r| SarifRule {
                id: r.id.to_string(),
                name: r.name.to_string(),
                short_description: SarifText {
                    text: r.short.to_string(),
                },
                full_description: SarifText {
                    text: r.full.to_string(),
                },
                help_uri: TOOL_URI.to_string(),
                default_configuration: SarifConfig {
                    level: "warning".to_string(),
                },
            })
            .collect();

        SarifDocument {
            schema: SARIF_SCHEMA.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: TOOL_NAME.to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: TOOL_URI.to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}

pub fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

// ── SARIF 2.1.0 ─────────────────────────────────────────────────────────────

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "pinprick";
const TOOL_URI: &str = "https://pinprick.rs";

struct RuleDef {
    id: &'static str,
    name: &'static str,
    short: &'static str,
    full: &'static str,
}

/// One rule per audit-pattern category. Rule IDs are stable and derived from
/// `audit_patterns::category_str`, so a new category requires a new entry here.
const SARIF_RULES: &[RuleDef] = &[
    RuleDef {
        id: "pinprick/shell_fetch",
        name: "ShellFetch",
        short: "Shell runtime fetch without pinning",
        full: "Shell commands (curl, wget, gh release download, go install, pip, npm, PowerShell Invoke-WebRequest) that download content at runtime without pinning to a specific version. These bypass action SHA pinning.",
    },
    RuleDef {
        id: "pinprick/javascript_fetch",
        name: "JavaScriptFetch",
        short: "JavaScript runtime fetch without pinning",
        full: "JavaScript or TypeScript code (fetch, axios, got, http.get, or child_process shelling out to curl/wget) that downloads content at runtime without pinning to a specific version.",
    },
    RuleDef {
        id: "pinprick/python_fetch",
        name: "PythonFetch",
        short: "Python runtime fetch without pinning",
        full: "Python code (urllib, requests, or subprocess shelling out to curl/wget) that downloads content at runtime without pinning to a specific version.",
    },
    RuleDef {
        id: "pinprick/docker_unpinned",
        name: "DockerUnpinned",
        short: "Docker image or RUN instruction without pinning",
        full: "Dockerfile FROM lines using `:latest` or no tag, or RUN instructions that download content without pinning. Prefer digest-pinned images and versioned downloads.",
    },
];

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

#[derive(Serialize)]
struct SarifDocument {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "fullDescription")]
    full_description: SarifText,
    #[serde(rename = "helpUri")]
    help_uri: String,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfig,
}

#[derive(Serialize)]
struct SarifConfig {
    level: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifText,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

#[cfg(test)]
mod sarif_tests {
    use super::*;
    use serde_json::Value;

    fn finding(severity: &str, category: &str) -> AuditFinding {
        AuditFinding {
            severity: severity.into(),
            category: category.into(),
            action: String::new(),
            source_file: ".github/workflows/ci.yml".into(),
            line: Some(42),
            pattern_matched: "curl -L https://example.com/latest/foo".into(),
            description: "unversioned curl".into(),
            workflow_file: None,
            workflow_line: None,
        }
    }

    fn report(findings: Vec<AuditFinding>) -> AuditReport {
        AuditReport {
            findings,
            allowed: vec![],
            actions_scanned: 0,
            had_token: false,
            audited_bundled: 0,
            audited_local_cache: 0,
            audited_remote: 0,
            scanned_fresh: 0,
            scanned_unpinned_branch: 0,
            scanned_unpinned_sliding: 0,
            ignored: 0,
        }
    }

    fn sarif(findings: Vec<AuditFinding>) -> Value {
        let doc = report(findings).build_sarif();
        let json = serde_json::to_string(&doc).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn document_has_schema_version_and_tool_metadata() {
        let v = sarif(vec![]);
        assert_eq!(v["version"], "2.1.0");
        assert!(
            v["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0.json")
        );
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "pinprick");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(driver["informationUri"], "https://pinprick.rs");
    }

    #[test]
    fn all_four_rules_enumerated() {
        let v = sarif(vec![]);
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 4);
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"pinprick/shell_fetch"));
        assert!(ids.contains(&"pinprick/javascript_fetch"));
        assert!(ids.contains(&"pinprick/python_fetch"));
        assert!(ids.contains(&"pinprick/docker_unpinned"));
        // Each rule has the required fields
        for rule in rules {
            assert!(rule["name"].is_string());
            assert!(rule["shortDescription"]["text"].is_string());
            assert!(rule["fullDescription"]["text"].is_string());
            assert!(rule["helpUri"].is_string());
            assert_eq!(rule["defaultConfiguration"]["level"], "warning");
        }
    }

    #[test]
    fn severity_maps_to_sarif_level() {
        let v = sarif(vec![
            finding("high", "shell_fetch"),
            finding("medium", "shell_fetch"),
            finding("low", "shell_fetch"),
        ]);
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
    }

    #[test]
    fn rule_id_derived_from_category() {
        let v = sarif(vec![
            finding("high", "javascript_fetch"),
            finding("medium", "docker_unpinned"),
        ]);
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["ruleId"], "pinprick/javascript_fetch");
        assert_eq!(results[1]["ruleId"], "pinprick/docker_unpinned");
    }

    #[test]
    fn local_finding_anchors_to_source_file_and_line() {
        let f = finding("high", "shell_fetch");
        let v = sarif(vec![f]);
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], ".github/workflows/ci.yml");
        assert_eq!(loc["region"]["startLine"], 42);
        // Message text is just the description — no " (in ...)" suffix
        assert_eq!(
            v["runs"][0]["results"][0]["message"]["text"],
            "unversioned curl"
        );
    }

    #[test]
    fn remote_finding_anchors_to_workflow_and_surfaces_remote_path() {
        let mut f = finding("medium", "javascript_fetch");
        f.source_file = "actions/checkout (dist/index.js)".into();
        f.line = Some(10_000);
        f.workflow_file = Some(".github/workflows/ci.yml".into());
        f.workflow_line = Some(7);

        let v = sarif(vec![f]);
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        // Anchored to the workflow file, not the remote path
        assert_eq!(loc["artifactLocation"]["uri"], ".github/workflows/ci.yml");
        assert_eq!(loc["region"]["startLine"], 7);
        // Remote path surfaced in the message instead
        let text = v["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("unversioned curl"));
        assert!(text.contains("actions/checkout (dist/index.js)"));
    }

    #[test]
    fn missing_line_defaults_to_one() {
        let mut f = finding("low", "shell_fetch");
        f.line = None;
        let v = sarif(vec![f]);
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["region"]["startLine"], 1);
    }

    #[test]
    fn empty_findings_produce_zero_results() {
        let v = sarif(vec![]);
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }
}

#[cfg(test)]
mod audit_summary_tests {
    use super::*;

    fn empty_report() -> AuditReport {
        AuditReport {
            findings: vec![],
            allowed: vec![],
            actions_scanned: 0,
            had_token: true,
            audited_bundled: 0,
            audited_local_cache: 0,
            audited_remote: 0,
            scanned_fresh: 0,
            scanned_unpinned_branch: 0,
            scanned_unpinned_sliding: 0,
            ignored: 0,
        }
    }

    fn lines_without_ansi(r: &AuditReport) -> Vec<String> {
        colored::control::set_override(false);
        let out = r.audit_summary_lines();
        colored::control::unset_override();
        out
    }

    #[test]
    fn empty_report_produces_no_summary() {
        let r = empty_report();
        assert!(lines_without_ansi(&r).is_empty());
    }

    #[test]
    fn only_bundled() {
        let r = AuditReport {
            audited_bundled: 5,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["Audited 5 actions: 5 bundled."]
        );
    }

    #[test]
    fn mixed_sources() {
        let r = AuditReport {
            audited_bundled: 5,
            audited_local_cache: 2,
            scanned_fresh: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["Audited 8 actions: 5 bundled, 2 local cache, 1 scanned fresh."]
        );
    }

    #[test]
    fn all_four_sources() {
        let r = AuditReport {
            audited_bundled: 3,
            audited_local_cache: 2,
            audited_remote: 1,
            scanned_fresh: 4,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["Audited 10 actions: 3 bundled, 2 local cache, 1 pinprick.rs, 4 scanned fresh."]
        );
    }

    #[test]
    fn ignored_only_emits_only_ignored_line() {
        let r = AuditReport {
            ignored: 2,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["2 actions ignored per config."]
        );
    }

    #[test]
    fn mixed_sources_plus_ignored() {
        let r = AuditReport {
            audited_bundled: 4,
            ignored: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec![
                "Audited 4 actions: 4 bundled.",
                "1 action ignored per config.",
            ]
        );
    }

    #[test]
    fn single_action_singular_plural() {
        let r = AuditReport {
            audited_bundled: 1,
            ..empty_report()
        };
        assert_eq!(lines_without_ansi(&r), vec!["Audited 1 action: 1 bundled."]);
    }

    #[test]
    fn sliding_tag_only_suggests_pinprick_pin() {
        let r = AuditReport {
            scanned_unpinned_sliding: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["1 sliding tag scanned. Run `pinprick pin` to resolve."]
        );
    }

    #[test]
    fn branch_ref_only_says_pin_manually() {
        let r = AuditReport {
            scanned_unpinned_branch: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["1 branch ref scanned. Pin to a SHA manually."]
        );
    }

    #[test]
    fn unpinned_and_pinned_are_split() {
        let r = AuditReport {
            audited_bundled: 3,
            scanned_unpinned_sliding: 2,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec![
                "Audited 3 actions: 3 bundled.",
                "2 sliding tags scanned. Run `pinprick pin` to resolve.",
            ]
        );
    }

    #[test]
    fn branch_and_sliding_are_separate_lines() {
        let r = AuditReport {
            scanned_unpinned_branch: 1,
            scanned_unpinned_sliding: 2,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec![
                "2 sliding tags scanned. Run `pinprick pin` to resolve.",
                "1 branch ref scanned. Pin to a SHA manually.",
            ]
        );
    }

    #[test]
    fn scanned_fresh_does_not_include_unpinned() {
        let r = AuditReport {
            scanned_fresh: 2,
            scanned_unpinned_sliding: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec![
                "Audited 2 actions: 2 scanned fresh.",
                "1 sliding tag scanned. Run `pinprick pin` to resolve.",
            ]
        );
    }

    #[test]
    fn all_categories_populated() {
        let r = AuditReport {
            audited_bundled: 5,
            audited_local_cache: 2,
            audited_remote: 1,
            scanned_fresh: 3,
            scanned_unpinned_sliding: 2,
            scanned_unpinned_branch: 1,
            ignored: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec![
                "Audited 11 actions: 5 bundled, 2 local cache, 1 pinprick.rs, 3 scanned fresh.",
                "2 sliding tags scanned. Run `pinprick pin` to resolve.",
                "1 branch ref scanned. Pin to a SHA manually.",
                "1 action ignored per config.",
            ]
        );
    }
}
