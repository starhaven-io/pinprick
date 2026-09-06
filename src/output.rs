use colored::Colorize;
use serde::Serialize;
use std::io::{self, Write};

use crate::audit_patterns::{Category, FindingKind, Pattern, Severity, category_str};

/// Replace control chars (C0/C1/DEL, except tab) with U+FFFD so escape sequences
/// in fetched action source can't spoof or hide findings in the terminal.
/// JSON/SARIF are unaffected — serde already escapes control chars.
pub(crate) fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            let directional_control = matches!(
                c,
                '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            );
            if (c == '\t' || !c.is_control()) && !directional_control {
                c
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

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
        self.write_human(&mut io::stdout())
            .expect("writing pin report");
    }

    fn write_human(&self, w: &mut impl Write) -> io::Result<()> {
        let mut current_file = String::new();

        for p in &self.pinned {
            if p.file != current_file {
                if !current_file.is_empty() {
                    writeln!(w)?;
                }
                writeln!(w, "{}", sanitize_for_terminal(&p.file).bold())?;
                current_file.clone_from(&p.file);
            }
            let action = sanitize_for_terminal(&p.action);
            let old_ref = sanitize_for_terminal(&p.old_ref);
            let tag = sanitize_for_terminal(&p.tag);
            writeln!(
                w,
                "  {} {} {} {}",
                action.cyan(),
                format!("@{old_ref}").dimmed(),
                "->".dimmed(),
                format!("@{}… # {tag}", &p.sha[..12]).green()
            )?;
        }

        for s in &self.skipped {
            if s.file != current_file {
                if !current_file.is_empty() {
                    writeln!(w)?;
                }
                writeln!(w, "{}", sanitize_for_terminal(&s.file).bold())?;
                current_file.clone_from(&s.file);
            }
            let action = sanitize_for_terminal(&s.action);
            let reason = sanitize_for_terminal(&s.reason);
            writeln!(
                w,
                "  {} {}",
                format!("! {action}").yellow(),
                format!("-- {reason}").dimmed()
            )?;
        }

        if !self.pinned.is_empty() || !self.skipped.is_empty() {
            writeln!(w)?;
        }

        let total_files: std::collections::HashSet<&str> =
            self.pinned.iter().map(|p| p.file.as_str()).collect();
        let verb = if self.applied { "Pinned" } else { "Would pin" };
        writeln!(
            w,
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
        )?;
        if !self.applied && !self.pinned.is_empty() {
            writeln!(w, "Run with {} to apply.", "--write".bold())?;
        }
        Ok(())
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
pub struct UpdateFailure {
    pub file: String,
    pub action: String,
    pub stage: String,
    pub error: String,
    pub line: usize,
}

#[derive(Serialize)]
pub struct UpdateReport {
    pub updates: Vec<UpdateResult>,
    pub failures: Vec<UpdateFailure>,
    pub skipped: Vec<UpdateFailure>,
    pub up_to_date: usize,
    pub applied: bool,
}

impl UpdateReport {
    pub fn print_human(&self) {
        self.write_human(&mut io::stdout())
            .expect("writing update report");
    }

    fn write_human(&self, w: &mut impl Write) -> io::Result<()> {
        if self.updates.is_empty() && self.failures.is_empty() && self.skipped.is_empty() {
            writeln!(w, "All pinned actions are up to date.")?;
            return Ok(());
        }

        let mut current_file = String::new();
        for u in &self.updates {
            if u.file != current_file {
                if !current_file.is_empty() {
                    writeln!(w)?;
                }
                writeln!(w, "{}", sanitize_for_terminal(&u.file).bold())?;
                current_file.clone_from(&u.file);
            }
            let action = sanitize_for_terminal(&u.action);
            let current_tag = sanitize_for_terminal(&u.current_tag);
            let latest_tag = sanitize_for_terminal(&u.latest_tag);
            writeln!(
                w,
                "  {} {} {} {}",
                action.cyan(),
                current_tag.dimmed(),
                "->".dimmed(),
                latest_tag.green()
            )?;
            if let Some(url) = &u.release_url {
                writeln!(w, "    {}", sanitize_for_terminal(url).dimmed())?;
            }
        }

        for failure in &self.failures {
            if failure.file != current_file {
                if !current_file.is_empty() {
                    writeln!(w)?;
                }
                writeln!(w, "{}", sanitize_for_terminal(&failure.file).bold())?;
                current_file.clone_from(&failure.file);
            }
            writeln!(
                w,
                "  {} {}",
                format!("! {}", sanitize_for_terminal(&failure.action)).red(),
                format!(
                    "-- {} failed: {}",
                    sanitize_for_terminal(&failure.stage),
                    sanitize_for_terminal(&failure.error)
                )
                .dimmed()
            )?;
        }

        for skipped in &self.skipped {
            if skipped.file != current_file {
                if !current_file.is_empty() {
                    writeln!(w)?;
                }
                writeln!(w, "{}", sanitize_for_terminal(&skipped.file).bold())?;
                current_file.clone_from(&skipped.file);
            }
            writeln!(
                w,
                "  {} {}",
                format!("? {}", sanitize_for_terminal(&skipped.action)).yellow(),
                format!(
                    "-- {} skipped: {}",
                    sanitize_for_terminal(&skipped.stage),
                    sanitize_for_terminal(&skipped.error)
                )
                .dimmed()
            )?;
        }

        writeln!(w)?;
        if !self.failures.is_empty() {
            writeln!(
                w,
                "Coverage incomplete: {} action check{} failed; no files were changed.",
                self.failures.len(),
                if self.failures.len() == 1 { "" } else { "s" }
            )?;
        } else if self.applied {
            writeln!(
                w,
                "{} update{} applied.",
                self.updates.len(),
                if self.updates.len() == 1 { "" } else { "s" }
            )?;
        } else if !self.updates.is_empty() {
            writeln!(
                w,
                "{} update{} available. Run with {} to apply.",
                self.updates.len(),
                if self.updates.len() == 1 { "" } else { "s" },
                "--write".bold()
            )?;
        } else {
            writeln!(w, "No updates found in the completed checks.")?;
        }
        if !self.skipped.is_empty() {
            writeln!(
                w,
                "Coverage incomplete: {} action{} had no version tag and {} skipped.",
                self.skipped.len(),
                if self.skipped.len() == 1 { "" } else { "s" },
                if self.skipped.len() == 1 {
                    "was"
                } else {
                    "were"
                }
            )?;
        }
        Ok(())
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
    #[serde(skip)]
    pub(crate) finding_kind: Option<FindingKind>,
}

impl AuditFinding {
    pub fn new(
        severity: &Severity,
        category: &Category,
        action_name: &str,
        source_file: &str,
        line: usize,
        pattern_matched: &str,
        description: impl Into<String>,
    ) -> Self {
        Self {
            severity: severity_str(severity).to_string(),
            category: category_str(category).to_string(),
            action: action_name.to_string(),
            source_file: source_file.to_string(),
            line: Some(line),
            pattern_matched: pattern_matched.trim().to_string(),
            description: description.into(),
            workflow_file: None,
            workflow_line: None,
            finding_kind: None,
        }
    }

    pub fn from_pattern(
        pattern: &Pattern,
        action_name: &str,
        source_file: &str,
        line: usize,
        pattern_matched: &str,
    ) -> Self {
        let mut finding = Self::new(
            &pattern.severity,
            &pattern.category,
            action_name,
            source_file,
            line,
            pattern_matched,
            pattern.description,
        );
        finding.finding_kind = pattern.finding_kind;
        finding
    }
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

impl AuditMatch {
    pub fn new(
        severity: &Severity,
        category: &Category,
        action_name: &str,
        source_file: &str,
        line: usize,
        pattern_matched: &str,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            severity: severity_str(severity).to_string(),
            category: category_str(category).to_string(),
            action: action_name.to_string(),
            source_file: source_file.to_string(),
            line: Some(line),
            pattern_matched: pattern_matched.trim().to_string(),
            reason: reason.into(),
        }
    }

    pub fn from_pattern(
        pattern: &Pattern,
        action_name: &str,
        source_file: &str,
        line: usize,
        pattern_matched: &str,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            &pattern.severity,
            &pattern.category,
            action_name,
            source_file,
            line,
            pattern_matched,
            reason,
        )
    }

    pub fn from_finding(finding: AuditFinding, reason: impl Into<String>) -> Self {
        Self {
            severity: finding.severity,
            category: finding.category,
            action: finding.action,
            source_file: finding.source_file,
            line: finding.line,
            pattern_matched: finding.pattern_matched,
            reason: reason.into(),
        }
    }
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
    /// Number of unique external actions that were NOT scanned because no
    /// GitHub token was available. Without this, a token-less `--json` run
    /// reports `actions_scanned: 0` and nothing else — a consumer could read
    /// silence as cleanliness.
    #[serde(default)]
    pub external_actions_skipped: usize,
    /// Whether every discovered workflow and reachable action source was
    /// inspected far enough to support a clean verdict.
    pub coverage_complete: bool,
    /// Concrete reasons a clean verdict is unavailable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_failures: Vec<String>,
}

impl AuditReport {
    pub fn print_human(&self, verbose: bool) {
        for f in &self.findings {
            let sev = match f.severity.as_str() {
                "high" => "HIGH".red().bold(),
                "medium" => "MEDIUM".yellow().bold(),
                _ => "LOW".dimmed(),
            };

            let source_file = sanitize_for_terminal(&f.source_file);
            let location = match f.line {
                Some(n) => format!("{source_file}:{n}"),
                None => source_file,
            };

            println!("{sev}  {}", location.bold());
            if !f.action.is_empty() {
                println!("      action: {}", sanitize_for_terminal(&f.action).cyan());
            }
            println!(
                "      {}",
                sanitize_for_terminal(&f.pattern_matched).dimmed()
            );
            println!("      {}", sanitize_for_terminal(&f.description));
            println!();
        }

        if verbose && !self.allowed.is_empty() {
            println!("{}", "Allowed (matched but passed check):".dimmed());
            for m in &self.allowed {
                let source_file = sanitize_for_terminal(&m.source_file);
                let location = match m.line {
                    Some(n) => format!("{source_file}:{n}"),
                    None => source_file,
                };
                println!("{}   {}", "OK".green().bold(), location.bold());
                if !m.action.is_empty() {
                    println!("      action: {}", sanitize_for_terminal(&m.action).cyan());
                }
                println!(
                    "      {}",
                    sanitize_for_terminal(&m.pattern_matched).dimmed()
                );
                println!("      reason: {}", m.reason.dimmed());
                println!();
            }
        }

        if self.findings.is_empty() && self.coverage_complete {
            println!("No runtime fetch risks found.");
        } else if self.findings.is_empty() {
            println!("No runtime fetch risks found in the completed portion of the scan.");
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

        if !self.coverage_complete {
            println!(
                "{}",
                "Coverage incomplete; no clean verdict was produced.".yellow()
            );
            for failure in &self.coverage_failures {
                println!("  - {}", sanitize_for_terminal(failure));
            }
        }

        if !self.had_token {
            let note = if self.external_actions_skipped > 0 {
                format!(
                    "Note: no GitHub token — {} external action{} not scanned.",
                    self.external_actions_skipped,
                    if self.external_actions_skipped == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            } else {
                "Note: no GitHub token — action source code was not scanned.".to_string()
            };
            println!("{}", note.dimmed());
        }
    }

    /// Build the summary of how actions were audited; lines with a zero
    /// count are omitted.
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
                                // SARIF requires startLine >= 1; 0 is the
                                // internal "not located" sentinel.
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
                properties: SarifProperties {
                    coverage_complete: self.coverage_complete,
                    coverage_failures: self.coverage_failures.clone(),
                },
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

// Immutable published URL — the spec repo's `master` branch has moved schema
// paths before, which would leave emitted documents pointing at a dead link.
const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
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
        full: "Shell commands (curl, wget, gh release download, git clone, go install, pip, npm, cargo install, gem install, PowerShell Invoke-WebRequest) that download content at runtime without pinning to a specific version. These bypass action SHA pinning.",
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
        short: "Docker image or runtime fetch without pinning",
        full: "Docker images using `:latest` or no tag, or Docker build/runtime instructions that download content without pinning. Prefer digest-pinned images and versioned downloads.",
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
    properties: SarifProperties,
}

#[derive(Serialize)]
struct SarifProperties {
    #[serde(rename = "pinprickCoverageComplete")]
    coverage_complete: bool,
    #[serde(rename = "pinprickCoverageFailures")]
    coverage_failures: Vec<String>,
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
            finding_kind: None,
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
            external_actions_skipped: 0,
            coverage_complete: true,
            coverage_failures: vec![],
        }
    }

    fn sarif(findings: Vec<AuditFinding>) -> Value {
        let doc = report(findings).build_sarif();
        let json = serde_json::to_string(&doc).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn audit_finding_json_skips_internal_finding_kind() {
        let mut finding = finding("high", "shell_fetch");
        finding.finding_kind = Some(FindingKind::PipeToShell);
        let json = serde_json::to_value(&finding).unwrap();
        assert!(json.get("finding_kind").is_none());
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
        assert_eq!(v["runs"][0]["properties"]["pinprickCoverageComplete"], true);
    }

    #[test]
    fn sarif_exposes_incomplete_coverage() {
        let mut report = report(vec![]);
        report.coverage_complete = false;
        report.coverage_failures = vec!["source fetch failed".to_string()];
        let json = serde_json::to_value(report.build_sarif()).unwrap();
        assert_eq!(
            json["runs"][0]["properties"]["pinprickCoverageComplete"],
            false
        );
        assert_eq!(
            json["runs"][0]["properties"]["pinprickCoverageFailures"][0],
            "source fetch failed"
        );
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
    fn every_category_has_sarif_rule_metadata() {
        use crate::audit_patterns::{Category, category_str};
        // The match is exhaustive on purpose: adding a Category variant fails
        // compilation here until the list below (and SARIF_RULES) grows with it.
        let all = [
            Category::DockerUnpinned,
            Category::JavaScriptFetch,
            Category::PythonFetch,
            Category::ShellFetch,
        ];
        for category in &all {
            match category {
                Category::DockerUnpinned
                | Category::JavaScriptFetch
                | Category::PythonFetch
                | Category::ShellFetch => {}
            }
            let id = format!("pinprick/{}", category_str(category));
            assert!(
                SARIF_RULES.iter().any(|r| r.id == id),
                "no SARIF rule metadata for category {id} — findings would carry a ruleId with no rule"
            );
        }
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
            external_actions_skipped: 0,
            coverage_complete: true,
            coverage_failures: vec![],
        }
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut in_escape = false;
        for c in s.chars() {
            if in_escape {
                if c.is_ascii_alphabetic() {
                    in_escape = false;
                }
            } else if c == '\x1b' {
                in_escape = true;
            } else {
                out.push(c);
            }
        }
        out
    }

    fn lines_without_ansi(r: &AuditReport) -> Vec<String> {
        r.audit_summary_lines()
            .into_iter()
            .map(|s| strip_ansi(&s))
            .collect()
    }

    #[test]
    fn sanitize_for_terminal_neutralizes_control_chars() {
        assert_eq!(sanitize_for_terminal("plain text"), "plain text");
        assert_eq!(sanitize_for_terminal("café → núñez"), "café → núñez");
        // Tab is the one control char kept.
        assert_eq!(sanitize_for_terminal("keep\ttab"), "keep\ttab");
        assert_eq!(sanitize_for_terminal("a\u{1b}[2Jb"), "a\u{fffd}[2Jb");
        assert_eq!(
            sanitize_for_terminal("x\ry\nz\u{7}\u{7f}"),
            "x\u{fffd}y\u{fffd}z\u{fffd}\u{fffd}"
        );
        assert_eq!(
            sanitize_for_terminal("safe\u{202e}gpj.exe\u{2066}"),
            "safe\u{fffd}gpj.exe\u{fffd}"
        );
    }

    #[test]
    fn pin_human_output_sanitizes_untrusted_fields() {
        let report = PinReport {
            pinned: vec![PinResult {
                file: ".github/workflows/ci.yml".into(),
                action: "evil\u{1b}[2J/action".into(),
                old_ref: "main\u{7}".into(),
                sha: "0123456789abcdef0123456789abcdef01234567".into(),
                tag: "v1.2.3\rrewrite".into(),
                line: 1,
            }],
            skipped: vec![PinSkip {
                file: ".github/workflows/ci.yml".into(),
                action: "skip\u{7f}action".into(),
                reason: "branch\u{1b}[31m ref".into(),
                line: 2,
            }],
            applied: false,
        };
        let mut buf = Vec::new();
        report.write_human(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("evil\u{fffd}[2J/action"));
        assert!(out.contains("@main\u{fffd}"));
        assert!(out.contains("# v1.2.3\u{fffd}rewrite"));
        assert!(out.contains("skip\u{fffd}action"));
        assert!(out.contains("branch\u{fffd}[31m ref"));
        assert!(out.contains("(1 skipped)"));
        assert!(!out.contains('\u{7}'));
        assert!(!out.contains('\r'));
        assert!(!out.contains('\u{7f}'));
    }

    #[test]
    fn pin_human_output_reports_applied_summary() {
        let report = PinReport {
            pinned: vec![PinResult {
                file: ".github/workflows/ci.yml".into(),
                action: "owner/action".into(),
                old_ref: "v1".into(),
                sha: "0123456789abcdef0123456789abcdef01234567".into(),
                tag: "v1".into(),
                line: 1,
            }],
            skipped: vec![],
            applied: true,
        };
        let mut buf = Vec::new();
        report.write_human(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Pinned 1 action across 1 file"));
        assert!(!out.contains("Would pin"));
    }

    #[test]
    fn update_human_output_sanitizes_untrusted_fields() {
        let report = UpdateReport {
            updates: vec![
                UpdateResult {
                    file: ".github/workflows/ci.yml".into(),
                    action: "evil\u{1b}[2J/action".into(),
                    current_tag: "v1\u{7}".into(),
                    current_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                    latest_tag: "v2\rrewrite".into(),
                    latest_sha: "abcdef0123456789abcdef0123456789abcdef01".into(),
                    line: 1,
                    release_url: Some("https://example.com/release\u{7f}".into()),
                },
                UpdateResult {
                    file: ".github/workflows/other.yml".into(),
                    action: "other/action".into(),
                    current_tag: "v1".into(),
                    current_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                    latest_tag: "v2".into(),
                    latest_sha: "abcdef0123456789abcdef0123456789abcdef01".into(),
                    line: 2,
                    release_url: None,
                },
            ],
            failures: Vec::new(),
            skipped: Vec::new(),
            up_to_date: 0,
            applied: true,
        };
        let mut buf = Vec::new();
        report.write_human(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("evil\u{fffd}[2J/action"));
        assert!(out.contains("v1\u{fffd}"));
        assert!(out.contains("v2\u{fffd}rewrite"));
        assert!(out.contains("https://example.com/release\u{fffd}"));
        assert!(out.contains("2 updates applied."));
        assert!(!out.contains('\u{7}'));
        assert!(!out.contains('\r'));
        assert!(!out.contains('\u{7f}'));
    }

    #[test]
    fn update_human_output_reports_empty_summary() {
        let empty = UpdateReport {
            updates: vec![],
            failures: Vec::new(),
            skipped: Vec::new(),
            up_to_date: 1,
            applied: false,
        };
        let mut buf = Vec::new();
        empty.write_human(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "All pinned actions are up to date.\n"
        );
    }

    #[test]
    fn update_human_output_reports_dry_run_summary() {
        let dry_run = UpdateReport {
            updates: vec![UpdateResult {
                file: ".github/workflows/ci.yml".into(),
                action: "owner/action".into(),
                current_tag: "v1".into(),
                current_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                latest_tag: "v2".into(),
                latest_sha: "abcdef0123456789abcdef0123456789abcdef01".into(),
                line: 1,
                release_url: None,
            }],
            failures: Vec::new(),
            skipped: Vec::new(),
            up_to_date: 0,
            applied: false,
        };
        let mut buf = Vec::new();
        dry_run.write_human(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("1 update available."));
        assert!(out.contains("--write"));
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

    #[test]
    fn local_cache_only() {
        let r = AuditReport {
            audited_local_cache: 3,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["Audited 3 actions: 3 local cache."]
        );
    }

    #[test]
    fn remote_only() {
        let r = AuditReport {
            audited_remote: 1,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["Audited 1 action: 1 pinprick.rs."]
        );
    }

    #[test]
    fn unpinned_only_no_audited_line() {
        let r = AuditReport {
            scanned_unpinned_sliding: 1,
            scanned_unpinned_branch: 2,
            ..empty_report()
        };
        let lines = lines_without_ansi(&r);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("1 sliding tag scanned"));
        assert!(lines[1].contains("2 branch refs scanned"));
    }

    #[test]
    fn plural_ignored() {
        let r = AuditReport {
            ignored: 5,
            ..empty_report()
        };
        assert_eq!(
            lines_without_ansi(&r),
            vec!["5 actions ignored per config."]
        );
    }
}
