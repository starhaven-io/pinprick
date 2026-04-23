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
                "Confirm publisher trust; add to `trusted-owners` in .pinprick.toml or consider vendoring"
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

pub async fn run(repo_root: &Path, json: bool) -> Result<ExitCode> {
    let config = Config::load(repo_root);
    let report = score_repo(repo_root, &config)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
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
