//! Scoring: turn workflow scan findings into a single posture grade.
//!
//! The rubric is specified in `docs/scoring.md`. Every rule id, point value,
//! and category here must match that document — the whole value of scoring
//! is that a third party can re-derive it from the public rubric.

use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use serde_norway::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;
use crate::workflow::{self, ActionRef, RefType};

pub const RUBRIC_VERSION: &str = "0.2.0";

// ── Rule catalog ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Pin,
    Source,
    Workflow,
    // Runtime category is in the rubric spec but has no rules implemented yet;
    // added alongside its rules.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleId {
    PinBranch,
    PinSliding,
    PinFullTag,
    SourceUnverified,
    WorkflowPermissionsWriteAll,
    WorkflowPullRequestTarget,
    WorkflowWorkflowRun,
}

impl RuleId {
    pub fn id(self) -> &'static str {
        match self {
            Self::PinBranch => "pin.branch",
            Self::PinSliding => "pin.sliding",
            Self::PinFullTag => "pin.full_tag",
            Self::SourceUnverified => "source.unverified",
            Self::WorkflowPermissionsWriteAll => "workflow.permissions_write_all",
            Self::WorkflowPullRequestTarget => "workflow.pull_request_target",
            Self::WorkflowWorkflowRun => "workflow.workflow_run",
        }
    }

    pub fn category(self) -> Category {
        match self {
            Self::PinBranch | Self::PinSliding | Self::PinFullTag => Category::Pin,
            Self::SourceUnverified => Category::Source,
            Self::WorkflowPermissionsWriteAll
            | Self::WorkflowPullRequestTarget
            | Self::WorkflowWorkflowRun => Category::Workflow,
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Self::PinBranch
            | Self::WorkflowPermissionsWriteAll
            | Self::WorkflowPullRequestTarget => Severity::High,
            Self::PinSliding | Self::WorkflowWorkflowRun => Severity::Medium,
            Self::PinFullTag | Self::SourceUnverified => Severity::Low,
        }
    }

    pub fn points(self) -> u32 {
        match self {
            Self::PinBranch => 15,
            Self::WorkflowPermissionsWriteAll => 10,
            Self::PinSliding => 5,
            Self::WorkflowPullRequestTarget => 5,
            Self::WorkflowWorkflowRun => 3,
            Self::PinFullTag => 2,
            Self::SourceUnverified => 1,
        }
    }

    pub fn remediation(self) -> &'static str {
        match self {
            Self::PinBranch | Self::PinSliding | Self::PinFullTag => {
                "Pin to a full 40-char SHA; keep the tag as a comment"
            }
            Self::SourceUnverified => {
                "Confirm this publisher is trustworthy. Add them to `trusted-owners` in .pinprick.toml, or fork the action into your own org and pin to that."
            }
            Self::WorkflowPermissionsWriteAll => {
                "Declare minimal per-job `permissions:` blocks instead of `write-all`"
            }
            Self::WorkflowPullRequestTarget => {
                "Validate the checkout ref; avoid running PR code with elevated tokens"
            }
            Self::WorkflowWorkflowRun => "Explicitly validate trigger provenance",
        }
    }
}

// ── Finding / Report types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Occurrence {
    pub workflow: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub points: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_ref: Option<String>,
    pub occurrences: Vec<Occurrence>,
    pub remediation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Totals {
    pub points_deducted: u32,
    pub findings: usize,
    pub workflows_scanned: usize,
    pub unique_actions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub kind: &'static str,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreReport {
    pub rubric_version: &'static str,
    pub pinprick_version: &'static str,
    pub target: Target,
    pub score: u32,
    pub grade: &'static str,
    pub totals: Totals,
    pub findings: Vec<Finding>,
}

// ── Scoring ─────────────────────────────────────────────────────────────────

pub fn grade_for(score: u32) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

/// Collect findings across all workflows, dedupe by rule + target, and roll
/// up into a single report.
pub fn score_repo(repo_root: &Path, config: &Config) -> Result<ScoreReport> {
    let files = workflow::find_workflows(repo_root)?;

    // Accumulate action-level findings keyed by (rule, action_ref).
    // Accumulate workflow-level findings keyed by (rule, workflow_path).
    let mut action_findings: BTreeMap<(RuleId, String), Vec<Occurrence>> = BTreeMap::new();
    let mut workflow_findings: BTreeMap<(RuleId, String), Vec<Occurrence>> = BTreeMap::new();
    let mut unique_actions: std::collections::BTreeSet<String> = Default::default();

    for file in &files {
        let display = workflow::display_path(file, repo_root);
        let content = std::fs::read_to_string(file)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;

        // Action-level findings (pin.*, source.*)
        for a in workflow::scan_content(&content) {
            let action_ref = format!("{}@{}", a.full_name(), a.ref_string);
            unique_actions.insert(action_ref.clone());

            if let Some(rule) = pin_rule_for(&a) {
                let key = (rule, action_ref.clone());
                action_findings.entry(key).or_default().push(Occurrence {
                    workflow: display.clone(),
                    line: a.line_number,
                });
            }

            if !config.is_owner_trusted(&a.owner) {
                let key = (RuleId::SourceUnverified, action_ref.clone());
                action_findings.entry(key).or_default().push(Occurrence {
                    workflow: display.clone(),
                    line: a.line_number,
                });
            }
        }

        // Workflow-level findings (workflow.*)
        let doc: Option<Value> = serde_norway::from_str(&content).ok();
        if let Some(doc) = doc {
            for rule in workflow_rules_for(&doc) {
                workflow_findings
                    .entry((rule, display.clone()))
                    .or_default()
                    .push(Occurrence {
                        workflow: display.clone(),
                        line: 0, // workflow-level finding has no specific line
                    });
            }
        }
    }

    let mut findings: Vec<Finding> = Vec::new();

    for ((rule, action_ref), mut occurrences) in action_findings {
        occurrences.sort_by(|a, b| a.workflow.cmp(&b.workflow).then(a.line.cmp(&b.line)));
        findings.push(Finding {
            id: rule.id(),
            category: rule.category(),
            severity: rule.severity(),
            points: rule.points(),
            action_ref: Some(action_ref),
            occurrences,
            remediation: rule.remediation(),
        });
    }

    for ((rule, _workflow_path), occurrences) in workflow_findings {
        findings.push(Finding {
            id: rule.id(),
            category: rule.category(),
            severity: rule.severity(),
            points: rule.points(),
            action_ref: None,
            occurrences,
            remediation: rule.remediation(),
        });
    }

    // Stable ordering: highest severity + highest points first, then rule id.
    findings.sort_by(|a, b| {
        b.points
            .cmp(&a.points)
            .then_with(|| a.id.cmp(b.id))
            .then_with(|| {
                a.action_ref
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.action_ref.as_deref().unwrap_or(""))
            })
    });

    let points_deducted: u32 = findings.iter().map(|f| f.points).sum();
    let score = 100u32.saturating_sub(points_deducted);

    Ok(ScoreReport {
        rubric_version: RUBRIC_VERSION,
        pinprick_version: env!("CARGO_PKG_VERSION"),
        target: Target {
            kind: "repo",
            path: repo_root.display().to_string(),
        },
        score,
        grade: grade_for(score),
        totals: Totals {
            points_deducted,
            findings: findings.len(),
            workflows_scanned: files.len(),
            unique_actions: unique_actions.len(),
        },
        findings,
    })
}

fn pin_rule_for(a: &ActionRef) -> Option<RuleId> {
    // `pin.none` (no `@ref`) is unreachable: the `uses:` parser rejects
    // lines without an `@ref`, so no-ref references never reach the scorer.
    match a.ref_type {
        RefType::Sha => None,
        RefType::Branch => Some(RuleId::PinBranch),
        RefType::SlidingTag => Some(RuleId::PinSliding),
        RefType::Tag => Some(RuleId::PinFullTag),
    }
}

fn workflow_rules_for(doc: &Value) -> Vec<RuleId> {
    let mut rules = Vec::new();

    // Top-level `permissions: write-all`
    if let Some(Value::String(s)) = doc.get("permissions")
        && s == "write-all"
    {
        rules.push(RuleId::WorkflowPermissionsWriteAll);
    }

    // `on.pull_request_target` — presence is the signal
    if let Some(on) = doc.get("on")
        && trigger_present(on, "pull_request_target")
    {
        rules.push(RuleId::WorkflowPullRequestTarget);
    }

    // `on.workflow_run`
    if let Some(on) = doc.get("on")
        && trigger_present(on, "workflow_run")
    {
        rules.push(RuleId::WorkflowWorkflowRun);
    }

    rules
}

fn trigger_present(on: &Value, name: &str) -> bool {
    match on {
        Value::String(s) => s == name,
        Value::Sequence(seq) => seq
            .iter()
            .any(|v| matches!(v, Value::String(s) if s == name)),
        Value::Mapping(map) => map
            .keys()
            .any(|k| matches!(k, Value::String(s) if s == name)),
        _ => false,
    }
}

// ── CLI entry point ─────────────────────────────────────────────────────────

pub async fn run(repo_root: &Path, json: bool, html: bool) -> Result<ExitCode> {
    let config = Config::load(repo_root);
    let report = score_repo(repo_root, &config)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if html {
        // render_html terminates its output with a newline already;
        // `print!` avoids a spurious trailing blank line.
        print!("{}", render_html(&report));
    } else {
        print_human(&report);
    }

    // Exit 1 whenever findings exist — matches `audit`'s convention so the
    // subcommand gates CI cleanly. Grade bands are a presentation detail.
    if report.findings.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn print_human(report: &ScoreReport) {
    let (grade_colored, _) = color_for_grade(report.grade);
    println!(
        "pinprick score  {} rubric",
        format!("v{}", report.rubric_version).dimmed()
    );
    println!();
    println!(
        "  Grade:  {}   ({} / 100)",
        grade_colored,
        report.score.to_string().bold()
    );
    println!();

    if report.findings.is_empty() {
        println!("  {}", "No findings.".green());
        return;
    }

    let total_occurrences: usize = report.findings.iter().map(|f| f.occurrences.len()).sum();
    println!(
        "  Findings ({} unique, {} occurrences):",
        report.totals.findings.to_string().bold(),
        total_occurrences.to_string().bold()
    );

    for f in &report.findings {
        let target = f
            .action_ref
            .as_deref()
            .or_else(|| f.occurrences.first().map(|o| o.workflow.as_str()))
            .unwrap_or("");
        let sev = severity_label(f.severity);
        println!(
            "    {}  -{:<3}  {:<32}  {}",
            sev,
            f.points,
            f.id.cyan(),
            target.dimmed()
        );
    }

    println!();
    println!(
        "  {} workflows scanned, {} unique actions.",
        report.totals.workflows_scanned, report.totals.unique_actions
    );
    println!();
    println!("  Run with {} for the full report.", "--json".bold());
}

fn color_for_grade(grade: &str) -> (colored::ColoredString, &'static str) {
    match grade {
        "A" => (grade.green().bold(), "green"),
        "B" => (grade.green(), "green"),
        "C" => (grade.yellow(), "yellow"),
        "D" => (grade.yellow().bold(), "yellow"),
        _ => (grade.red().bold(), "red"),
    }
}

fn severity_label(s: Severity) -> colored::ColoredString {
    match s {
        Severity::High => "high  ".red(),
        Severity::Medium => "medium".yellow(),
        Severity::Low => "low   ".dimmed(),
    }
}

// ── HTML rendering ──────────────────────────────────────────────────────────

const HTML_CSS: &str = r#":root{--bg:#0f1419;--fg:#e6edf3;--muted:#7d8590;--accent:#58a6ff;--border:#30363d;--a:#2da44e;--b:#7eb36a;--c:#d29922;--d:#f0883e;--f:#da3633}*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}.container{max-width:960px;margin:0 auto;padding:2rem 1.5rem}.header{display:flex;align-items:baseline;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}.title{font-size:1.5rem;font-weight:600}.version{color:var(--muted);font-size:.875rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.grade-banner{display:flex;align-items:center;gap:2rem;padding:2rem;border-radius:12px;border:1px solid var(--border);background:rgba(255,255,255,.02);margin-bottom:2rem;flex-wrap:wrap}.grade{font-size:5rem;font-weight:700;line-height:1}.grade-A{color:var(--a)}.grade-B{color:var(--b)}.grade-C{color:var(--c)}.grade-D{color:var(--d)}.grade-F{color:var(--f)}.score-number{font-size:2.25rem;font-weight:500}.totals{color:var(--muted);font-size:.875rem;margin-top:.25rem}.no-findings{text-align:center;padding:3rem 1rem;color:var(--muted);font-size:1rem}h2{font-size:1.125rem;margin:2rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}.finding{padding:1rem 0;border-bottom:1px solid var(--border)}.finding:last-child{border-bottom:none}.finding-header{display:flex;align-items:baseline;gap:.75rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.875rem;flex-wrap:wrap}.severity{font-size:.6875rem;text-transform:uppercase;padding:.15rem .5rem;border-radius:4px;letter-spacing:.03em;font-family:-apple-system,system-ui,sans-serif;font-weight:600}.severity-high{background:rgba(218,54,51,.15);color:var(--f)}.severity-medium{background:rgba(210,153,34,.15);color:var(--c)}.severity-low{background:rgba(125,133,144,.15);color:var(--muted)}.points{color:var(--muted);min-width:2.5rem}.rule-id{color:var(--accent)}.target{color:var(--muted);word-break:break-all}.remediation{margin-top:.5rem;font-size:.9375rem}.occurrences{margin:.5rem 0 0;padding:0 0 0 1.25rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8125rem;color:var(--muted)}.occurrences li{margin:.125rem 0}.footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--muted);font-size:.8125rem}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}"#;

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

pub fn render_html(report: &ScoreReport) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str(
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>",
    );
    out.push_str("pinprick score report");
    out.push_str("</title>\n<style>");
    out.push_str(HTML_CSS);
    out.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    // Header
    out.push_str("<div class=\"header\">\n  <div class=\"title\">pinprick score</div>\n");
    out.push_str(&format!(
        "  <div class=\"version\">rubric v{} · pinprick {}</div>\n</div>\n",
        escape_html(report.rubric_version),
        escape_html(report.pinprick_version)
    ));

    // Grade banner
    out.push_str(&format!(
        "<div class=\"grade-banner\">\n  <div class=\"grade grade-{0}\">{0}</div>\n  <div>\n    <div class=\"score-number\">{1} / 100</div>\n    <div class=\"totals\">{2} workflows scanned · {3} unique actions · {4} findings</div>\n  </div>\n</div>\n",
        escape_html(report.grade),
        report.score,
        report.totals.workflows_scanned,
        report.totals.unique_actions,
        report.totals.findings
    ));

    // Findings
    if report.findings.is_empty() {
        out.push_str("<div class=\"no-findings\">No findings. ");
        out.push_str(&escape_html(&format!(
            "{} workflows scanned.",
            report.totals.workflows_scanned
        )));
        out.push_str("</div>\n");
    } else {
        out.push_str("<h2>Prioritized fix list</h2>\n");
        for f in &report.findings {
            let target = f
                .action_ref
                .as_deref()
                .or_else(|| f.occurrences.first().map(|o| o.workflow.as_str()))
                .unwrap_or("");
            out.push_str("<div class=\"finding\">\n");
            out.push_str(&format!(
                "  <div class=\"finding-header\">\n    <span class=\"severity severity-{0}\">{0}</span>\n    <span class=\"points\">-{1}</span>\n    <span class=\"rule-id\">{2}</span>\n    <span class=\"target\">{3}</span>\n  </div>\n",
                severity_class(f.severity),
                f.points,
                escape_html(f.id),
                escape_html(target)
            ));
            out.push_str(&format!(
                "  <div class=\"remediation\">{}</div>\n",
                escape_html(f.remediation)
            ));
            if !f.occurrences.is_empty() {
                out.push_str("  <ul class=\"occurrences\">\n");
                for occ in &f.occurrences {
                    if occ.line > 0 {
                        out.push_str(&format!(
                            "    <li>{}:{}</li>\n",
                            escape_html(&occ.workflow),
                            occ.line
                        ));
                    } else {
                        out.push_str(&format!("    <li>{}</li>\n", escape_html(&occ.workflow)));
                    }
                }
                out.push_str("  </ul>\n");
            }
            out.push_str("</div>\n");
        }
    }

    // Footer
    out.push_str("<div class=\"footer\">\n  Generated by <a href=\"https://pinprick.rs\">pinprick</a>. Scoring rubric: <a href=\"https://github.com/starhaven-io/pinprick/blob/main/docs/scoring.md\">docs/scoring.md</a>.\n</div>\n");

    out.push_str("</div>\n</body>\n</html>\n");
    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_bands() {
        assert_eq!(grade_for(100), "A");
        assert_eq!(grade_for(90), "A");
        assert_eq!(grade_for(89), "B");
        assert_eq!(grade_for(80), "B");
        assert_eq!(grade_for(79), "C");
        assert_eq!(grade_for(70), "C");
        assert_eq!(grade_for(69), "D");
        assert_eq!(grade_for(60), "D");
        assert_eq!(grade_for(59), "F");
        assert_eq!(grade_for(0), "F");
    }

    #[test]
    fn pin_rule_for_each_ref_type() {
        use crate::workflow::parse_uses_line;

        let sha = parse_uses_line(
            "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6",
            1,
        )
        .unwrap();
        assert_eq!(pin_rule_for(&sha), None);

        let branch = parse_uses_line("      - uses: foo/bar@main", 1).unwrap();
        assert_eq!(pin_rule_for(&branch), Some(RuleId::PinBranch));

        let sliding = parse_uses_line("      - uses: actions/checkout@v4", 1).unwrap();
        assert_eq!(pin_rule_for(&sliding), Some(RuleId::PinSliding));

        let full_tag = parse_uses_line("      - uses: actions/checkout@v4.2.1", 1).unwrap();
        assert_eq!(pin_rule_for(&full_tag), Some(RuleId::PinFullTag));
    }

    #[test]
    fn workflow_rules_permissions_write_all() {
        let yaml = "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(rules.contains(&RuleId::WorkflowPermissionsWriteAll));
    }

    #[test]
    fn workflow_rules_no_permissions_block() {
        let yaml = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(!rules.contains(&RuleId::WorkflowPermissionsWriteAll));
    }

    #[test]
    fn workflow_rules_permissions_map_is_fine() {
        let yaml =
            "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(!rules.contains(&RuleId::WorkflowPermissionsWriteAll));
    }

    #[test]
    fn workflow_rules_pull_request_target_string_form() {
        let yaml = "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(rules.contains(&RuleId::WorkflowPullRequestTarget));
    }

    #[test]
    fn workflow_rules_pull_request_target_list_form() {
        let yaml =
            "on:\n  - push\n  - pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(rules.contains(&RuleId::WorkflowPullRequestTarget));
    }

    #[test]
    fn workflow_rules_pull_request_target_map_form() {
        let yaml = "on:\n  pull_request_target:\n    branches: [main]\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(rules.contains(&RuleId::WorkflowPullRequestTarget));
    }

    #[test]
    fn workflow_rules_workflow_run_map_form() {
        let yaml = "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\njobs:\n  a:\n    runs-on: ubuntu-latest\n";
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        let rules = workflow_rules_for(&doc);
        assert!(rules.contains(&RuleId::WorkflowWorkflowRun));
    }

    #[test]
    fn worked_example_from_spec() {
        // Reproduces the worked example in docs/scoring.md.
        // One workflow with: sliding tag (5) + full tag (2) + branch (15) +
        // permissions: write-all (10). No runtime rules implemented yet.
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = r#"
name: ci
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4.2.1
      - uses: some-org/custom-action@main
"#;
        std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        // pin.sliding (5) + pin.full_tag (2) + pin.branch (15)
        //   + workflow.permissions_write_all (10)
        //   + source.unverified for some-org/custom-action (1)
        //   = 33; score = 67; grade = D
        assert_eq!(report.totals.points_deducted, 33);
        assert_eq!(report.score, 67);
        assert_eq!(report.grade, "D");
    }

    #[test]
    fn clean_repo_scores_100() {
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = r#"
name: ci
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
"#;
        std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        assert_eq!(report.score, 100);
        assert_eq!(report.grade, "A");
        assert!(report.findings.is_empty());
    }

    #[test]
    fn dedupes_same_action_across_workflows() {
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
        std::fs::write(wfdir.join("a.yml"), yaml).unwrap();
        std::fs::write(wfdir.join("b.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        // Two workflows, same sliding-tag action -> ONE finding with 2 occurrences.
        let pin_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id == "pin.sliding")
            .collect();
        assert_eq!(pin_findings.len(), 1);
        assert_eq!(pin_findings[0].occurrences.len(), 2);
        // And the deduction is a single 5, not 10.
        assert_eq!(report.totals.points_deducted, 5);
    }

    // Exhaustive check that every RuleId variant has consistent id/category/
    // severity/points/remediation — easy to catch a missing match arm when
    // adding rules, and keeps every variant's helpers exercised.
    #[test]
    fn every_rule_id_has_metadata() {
        for rule in [
            RuleId::PinBranch,
            RuleId::PinSliding,
            RuleId::PinFullTag,
            RuleId::WorkflowPermissionsWriteAll,
            RuleId::WorkflowPullRequestTarget,
            RuleId::WorkflowWorkflowRun,
        ] {
            assert!(!rule.id().is_empty(), "rule {rule:?} has empty id");
            assert!(
                !rule.remediation().is_empty(),
                "rule {rule:?} has empty remediation"
            );
            assert!(rule.points() > 0, "rule {rule:?} has zero points");
            // Just call category/severity to exercise every match arm.
            let _ = rule.category();
            let _ = rule.severity();
        }
    }

    #[test]
    fn pull_request_target_and_workflow_run_score_end_to_end() {
        // Covers the id/points/remediation arms for PullRequestTarget and
        // WorkflowRun by firing both rules through score_repo.
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = r#"
name: x
on:
  pull_request_target:
    branches: [main]
  workflow_run:
    workflows: [CI]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
"#;
        std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"workflow.pull_request_target"));
        assert!(ids.contains(&"workflow.workflow_run"));
        // 5 + 3 = 8
        assert_eq!(report.totals.points_deducted, 8);
        assert_eq!(report.score, 92);
        assert_eq!(report.grade, "A");
    }

    #[test]
    fn source_unverified_fires_for_untrusted_owner() {
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: random-vendor/tool@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v1\n";
        std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
        assert_eq!(ids, vec!["source.unverified"]);
        assert_eq!(report.score, 99);
    }

    #[test]
    fn source_unverified_skipped_for_trusted_baseline() {
        // `actions` and `github` are in the built-in baseline.
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6\n      - uses: github/codeql-action/init@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v3\n";
        std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.score, 100);
    }

    #[test]
    fn source_unverified_respects_config_trusted_owners() {
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: my-vendor/tool@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v1\n";
        std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();

        let cfg = Config {
            trusted_owners: vec!["my-vendor".to_string()],
            ..Config::default()
        };
        let report = score_repo(dir.path(), &cfg).unwrap();
        assert!(report.findings.is_empty());
    }

    #[test]
    fn escape_html_handles_all_entities() {
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_html("'apos'"), "&#39;apos&#39;");
        assert_eq!(escape_html("plain text"), "plain text");
    }

    #[test]
    fn render_html_clean_report() {
        let report = ScoreReport {
            rubric_version: RUBRIC_VERSION,
            pinprick_version: env!("CARGO_PKG_VERSION"),
            target: Target {
                kind: "repo",
                path: ".".to_string(),
            },
            score: 100,
            grade: "A",
            totals: Totals {
                points_deducted: 0,
                findings: 0,
                workflows_scanned: 3,
                unique_actions: 7,
            },
            findings: vec![],
        };
        let html = render_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("grade-A"));
        assert!(html.contains("100 / 100"));
        assert!(html.contains("No findings"));
        assert!(html.contains("3 workflows scanned"));
        assert!(html.ends_with("</html>\n"));
    }

    #[test]
    fn render_html_with_findings_includes_remediations_and_occurrences() {
        let report = ScoreReport {
            rubric_version: RUBRIC_VERSION,
            pinprick_version: env!("CARGO_PKG_VERSION"),
            target: Target {
                kind: "repo",
                path: ".".to_string(),
            },
            score: 80,
            grade: "B",
            totals: Totals {
                points_deducted: 20,
                findings: 1,
                workflows_scanned: 2,
                unique_actions: 4,
            },
            findings: vec![Finding {
                id: "pin.branch",
                category: Category::Pin,
                severity: Severity::High,
                points: 15,
                action_ref: Some("foo/bar@main".to_string()),
                occurrences: vec![
                    Occurrence {
                        workflow: ".github/workflows/ci.yml".to_string(),
                        line: 22,
                    },
                    Occurrence {
                        workflow: ".github/workflows/release.yml".to_string(),
                        line: 15,
                    },
                ],
                remediation: "Pin to a full 40-char SHA; keep the tag as a comment",
            }],
        };
        let html = render_html(&report);
        assert!(html.contains("grade-B"));
        assert!(html.contains("80 / 100"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("pin.branch"));
        assert!(html.contains("foo/bar@main"));
        assert!(html.contains("ci.yml:22"));
        assert!(html.contains("release.yml:15"));
        assert!(html.contains("Pin to a full 40-char SHA"));
        assert!(html.contains("Prioritized fix list"));
    }

    #[test]
    fn render_html_escapes_user_content() {
        // Exercise the escaping path for action refs / workflow paths that
        // could (in theory) contain HTML metacharacters.
        let report = ScoreReport {
            rubric_version: RUBRIC_VERSION,
            pinprick_version: env!("CARGO_PKG_VERSION"),
            target: Target {
                kind: "repo",
                path: ".".to_string(),
            },
            score: 99,
            grade: "A",
            totals: Totals {
                points_deducted: 1,
                findings: 1,
                workflows_scanned: 1,
                unique_actions: 1,
            },
            findings: vec![Finding {
                id: "source.unverified",
                category: Category::Source,
                severity: Severity::Low,
                points: 1,
                action_ref: Some("<evil>/bar@v1".to_string()),
                occurrences: vec![Occurrence {
                    workflow: "a&b.yml".to_string(),
                    line: 1,
                }],
                remediation: "fix it",
            }],
        };
        let html = render_html(&report);
        assert!(!html.contains("<evil>"));
        assert!(html.contains("&lt;evil&gt;"));
        assert!(html.contains("a&amp;b.yml"));
    }

    #[test]
    fn print_human_does_not_panic_across_grades() {
        // Exercises print_human, color_for_grade, and severity_label for
        // clean and populated reports. We don't assert on stdout content
        // (terminal formatting is not worth locking down) — just that the
        // rendering paths don't panic and reach every helper branch.
        let clean = ScoreReport {
            rubric_version: RUBRIC_VERSION,
            pinprick_version: env!("CARGO_PKG_VERSION"),
            target: Target {
                kind: "repo",
                path: ".".to_string(),
            },
            score: 100,
            grade: "A",
            totals: Totals {
                points_deducted: 0,
                findings: 0,
                workflows_scanned: 0,
                unique_actions: 0,
            },
            findings: vec![],
        };
        print_human(&clean);

        let populated = ScoreReport {
            rubric_version: RUBRIC_VERSION,
            pinprick_version: env!("CARGO_PKG_VERSION"),
            target: Target {
                kind: "repo",
                path: ".".to_string(),
            },
            score: 55,
            grade: "F",
            totals: Totals {
                points_deducted: 45,
                findings: 3,
                workflows_scanned: 1,
                unique_actions: 3,
            },
            findings: vec![
                Finding {
                    id: "pin.branch",
                    category: Category::Pin,
                    severity: Severity::High,
                    points: 15,
                    action_ref: Some("foo/bar@main".to_string()),
                    occurrences: vec![Occurrence {
                        workflow: ".github/workflows/ci.yml".to_string(),
                        line: 10,
                    }],
                    remediation: "Pin to SHA",
                },
                Finding {
                    id: "pin.sliding",
                    category: Category::Pin,
                    severity: Severity::Medium,
                    points: 5,
                    action_ref: Some("actions/checkout@v4".to_string()),
                    occurrences: vec![Occurrence {
                        workflow: ".github/workflows/ci.yml".to_string(),
                        line: 12,
                    }],
                    remediation: "Pin to SHA",
                },
                Finding {
                    id: "workflow.permissions_write_all",
                    category: Category::Workflow,
                    severity: Severity::High,
                    points: 10,
                    action_ref: None,
                    occurrences: vec![Occurrence {
                        workflow: ".github/workflows/ci.yml".to_string(),
                        line: 0,
                    }],
                    remediation: "Declare minimal permissions",
                },
            ],
        };
        print_human(&populated);

        // Touch every grade band's color path.
        for grade in ["A", "B", "C", "D", "F"] {
            let _ = color_for_grade(grade);
        }
        // And every severity label.
        let _ = severity_label(Severity::Low);
        let _ = severity_label(Severity::Medium);
        let _ = severity_label(Severity::High);
    }
}
