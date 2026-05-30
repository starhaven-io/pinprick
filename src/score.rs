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

use crate::audit::{self, AuditCollector};
use crate::auth;
use crate::config::Config;
use crate::github::{AdvisoryVulnerability, GitHubClient, GitHubError, SecurityAdvisory};
use crate::output::AuditFinding;
use crate::workflow::{self, ActionRef, RefType};

pub const RUBRIC_VERSION: &str = "0.5.0";

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
    Runtime,
    Workflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleId {
    PinBranch,
    PinSliding,
    PinFullTag,
    SourceAdvisory,
    SourceArchived,
    SourceUnverified,
    RuntimePipeToShell,
    RuntimeFetchHigh,
    RuntimeFetchMedium,
    RuntimeFetchLow,
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
            Self::SourceAdvisory => "source.advisory",
            Self::SourceArchived => "source.archived",
            Self::SourceUnverified => "source.unverified",
            Self::RuntimePipeToShell => "runtime.pipe_to_shell",
            Self::RuntimeFetchHigh => "runtime.fetch.high",
            Self::RuntimeFetchMedium => "runtime.fetch.medium",
            Self::RuntimeFetchLow => "runtime.fetch.low",
            Self::WorkflowPermissionsWriteAll => "workflow.permissions_write_all",
            Self::WorkflowPullRequestTarget => "workflow.pull_request_target",
            Self::WorkflowWorkflowRun => "workflow.workflow_run",
        }
    }

    pub fn category(self) -> Category {
        match self {
            Self::PinBranch | Self::PinSliding | Self::PinFullTag => Category::Pin,
            Self::SourceAdvisory | Self::SourceArchived | Self::SourceUnverified => {
                Category::Source
            }
            Self::RuntimePipeToShell
            | Self::RuntimeFetchHigh
            | Self::RuntimeFetchMedium
            | Self::RuntimeFetchLow => Category::Runtime,
            Self::WorkflowPermissionsWriteAll
            | Self::WorkflowPullRequestTarget
            | Self::WorkflowWorkflowRun => Category::Workflow,
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Self::PinBranch
            | Self::SourceAdvisory
            | Self::SourceArchived
            | Self::RuntimePipeToShell
            | Self::RuntimeFetchHigh
            | Self::WorkflowPermissionsWriteAll
            | Self::WorkflowPullRequestTarget => Severity::High,
            Self::PinSliding | Self::RuntimeFetchMedium | Self::WorkflowWorkflowRun => {
                Severity::Medium
            }
            Self::PinFullTag | Self::SourceUnverified | Self::RuntimeFetchLow => Severity::Low,
        }
    }

    pub fn points(self) -> u32 {
        match self {
            Self::RuntimePipeToShell => 20,
            Self::PinBranch | Self::SourceAdvisory | Self::RuntimeFetchHigh => 15,
            Self::SourceArchived | Self::WorkflowPermissionsWriteAll => 10,
            Self::RuntimeFetchMedium => 8,
            Self::PinSliding | Self::WorkflowPullRequestTarget => 5,
            Self::RuntimeFetchLow | Self::WorkflowWorkflowRun => 3,
            Self::PinFullTag => 2,
            Self::SourceUnverified => 1,
        }
    }

    pub fn remediation(self) -> &'static str {
        match self {
            Self::PinBranch | Self::PinSliding | Self::PinFullTag => {
                "Pin to a full 40-char SHA; keep the tag as a comment"
            }
            Self::SourceAdvisory => {
                "Update past the vulnerable version range; see the referenced GHSA"
            }
            Self::SourceArchived => "Migrate to an actively maintained replacement",
            Self::SourceUnverified => {
                "Confirm this publisher is trustworthy. Add them to `trusted-owners` in .pinprick.toml, or fork the action into your own org and pin to that."
            }
            Self::RuntimePipeToShell => {
                "Download the payload to disk, verify it (checksum or signature), then execute. Never pipe directly to a shell."
            }
            Self::RuntimeFetchHigh => {
                "Pin the fetched artifact to a specific version; add checksum or signature verification"
            }
            Self::RuntimeFetchMedium => "Pin or version-lock the fetched resource",
            Self::RuntimeFetchLow => {
                "Review the fetch; often acceptable when the URL is explicitly versioned"
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
    /// Optional per-finding context (e.g., the GHSA id and URL behind a
    /// `source.advisory` finding). Static rule metadata stays in the rule
    /// id / remediation; this field carries the bits that vary per match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
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
    // Runtime findings are per-line and not deduped — each emitted finding is
    // a distinct fix in a distinct place.
    let mut action_findings: BTreeMap<(RuleId, String), Vec<Occurrence>> = BTreeMap::new();
    let mut workflow_findings: BTreeMap<(RuleId, String), Vec<Occurrence>> = BTreeMap::new();
    let mut runtime_findings: Vec<Finding> = Vec::new();
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

        // Runtime findings (runtime.*) — reuse the audit pipeline's shell
        // scanner on each `run:` block.
        if let Ok(run_blocks) = audit::extract_run_blocks(file, &content) {
            let mut collector = AuditCollector::new(false);
            for (line_offset, run_content) in &run_blocks {
                audit::scan_shell_content(
                    run_content,
                    &display,
                    *line_offset,
                    "",
                    &mut collector,
                    config,
                );
            }
            for finding in &collector.findings {
                // Honor `ignore.patterns` (an accepted risk shouldn't score) but
                // not the `severity` display threshold — the score is complete.
                if config.is_pattern_ignored(&finding.description) {
                    continue;
                }
                let rule = runtime_rule_for(finding);
                runtime_findings.push(Finding {
                    id: rule.id(),
                    category: rule.category(),
                    severity: rule.severity(),
                    points: rule.points(),
                    action_ref: None,
                    occurrences: vec![Occurrence {
                        workflow: display.clone(),
                        line: finding.line.unwrap_or(0),
                    }],
                    remediation: rule.remediation(),
                    details: None,
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
            details: None,
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
            details: None,
        });
    }

    findings.extend(runtime_findings);

    let mut report = ScoreReport {
        rubric_version: RUBRIC_VERSION,
        pinprick_version: env!("CARGO_PKG_VERSION"),
        target: Target {
            kind: "repo",
            path: repo_root.display().to_string(),
        },
        score: 100,
        grade: "A",
        totals: Totals {
            points_deducted: 0,
            findings: 0,
            workflows_scanned: files.len(),
            unique_actions: unique_actions.len(),
        },
        findings,
    };
    recompute_score(&mut report);
    Ok(report)
}

/// Sort findings (highest deduction first, then by rule id, then by action ref)
/// and recompute the report's totals, score, and grade. `workflows_scanned` and
/// `unique_actions` are set once by `score_repo` and are not touched here.
fn recompute_score(report: &mut ScoreReport) {
    report.findings.sort_by(|a, b| {
        b.points
            .cmp(&a.points)
            .then_with(|| a.id.cmp(b.id))
            .then_with(|| {
                a.action_ref
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.action_ref.as_deref().unwrap_or(""))
            })
            // Two `source.advisory` findings for the same action share id, points,
            // and action_ref; the details (GHSA id) make the order deterministic.
            .then_with(|| a.details.cmp(&b.details))
    });
    let points_deducted: u32 = report.findings.iter().map(|f| f.points).sum();
    let score = 100u32.saturating_sub(points_deducted);
    report.totals.points_deducted = points_deducted;
    report.totals.findings = report.findings.len();
    report.score = score;
    report.grade = grade_for(score);
}

/// A systemic failure (bad token, rate limit) vs. a per-repo 404/network blip —
/// enrichment must not silently grade a repo clean on one of these.
fn is_hard_github_error(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<GitHubError>(),
        Some(GitHubError::AuthRequired | GitHubError::RateLimit)
    )
}

/// Warn (to stderr, so JSON/HTML stdout stays clean) that a token-gated rule
/// couldn't complete — the score still emits but is incomplete.
fn warn_enrichment_incomplete(rule: &str, e: &anyhow::Error) {
    eprintln!(
        "warning: {rule} could not be evaluated ({e}); score reflects only the rules that ran"
    );
}

/// Fire `source.archived` findings for any pinned action whose repo is
/// archived on GitHub. Requires a token; the caller has already resolved one.
///
/// API calls are cached per `(owner, repo)` since archived status is a
/// repo-level property. A failed lookup (404, network) is silently treated
/// as "not archived" — same degradation pattern as `audit` when remote
/// fetches fail. We don't want one bad repo to nuke the whole scan.
async fn enrich_with_source_archived(
    report: &mut ScoreReport,
    repo_root: &Path,
    client: &GitHubClient,
) -> Result<()> {
    let files = workflow::find_workflows(repo_root)?;

    // action_ref -> occurrences
    let mut occurrences: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
    // action_ref -> (owner, repo)
    let mut action_repo: BTreeMap<String, (String, String)> = BTreeMap::new();

    for file in &files {
        let display = workflow::display_path(file, repo_root);
        let content = std::fs::read_to_string(file)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
        for a in workflow::scan_content(&content) {
            let action_ref = format!("{}@{}", a.full_name(), a.ref_string);
            action_repo
                .entry(action_ref.clone())
                .or_insert((a.owner.clone(), a.repo.clone()));
            occurrences.entry(action_ref).or_default().push(Occurrence {
                workflow: display.clone(),
                line: a.line_number,
            });
        }
    }

    let mut archived_cache: BTreeMap<(String, String), bool> = BTreeMap::new();
    for (owner, repo) in action_repo.values() {
        let key = (owner.clone(), repo.clone());
        if archived_cache.contains_key(&key) {
            continue;
        }
        let archived = match client.is_archived(owner, repo).await {
            Ok(archived) => archived,
            Err(e) if is_hard_github_error(&e) => {
                warn_enrichment_incomplete("source.archived", &e);
                return Ok(());
            }
            // A per-repo 404 or network blip shouldn't nuke the whole scan.
            Err(_) => false,
        };
        archived_cache.insert(key, archived);
    }

    let new_findings = archived_findings(&action_repo, &archived_cache, &occurrences);
    if !new_findings.is_empty() {
        report.findings.extend(new_findings);
        recompute_score(report);
    }
    Ok(())
}

/// Pure helper: build the `source.archived` findings for any `action_ref`
/// whose `(owner, repo)` is marked archived. Pulled out of
/// `enrich_with_source_archived` so the logic is reachable from unit tests
/// without a live `GitHubClient`.
fn archived_findings(
    action_repo: &BTreeMap<String, (String, String)>,
    archived: &BTreeMap<(String, String), bool>,
    occurrences: &BTreeMap<String, Vec<Occurrence>>,
) -> Vec<Finding> {
    let rule = RuleId::SourceArchived;
    let mut out = Vec::new();
    for (action_ref, owner_repo) in action_repo {
        if archived.get(owner_repo) != Some(&true) {
            continue;
        }
        let mut occs = occurrences.get(action_ref).cloned().unwrap_or_default();
        occs.sort_by(|a, b| a.workflow.cmp(&b.workflow).then(a.line.cmp(&b.line)));
        out.push(Finding {
            id: rule.id(),
            category: rule.category(),
            severity: rule.severity(),
            points: rule.points(),
            action_ref: Some(action_ref.clone()),
            occurrences: occs,
            remediation: rule.remediation(),
            details: None,
        });
    }
    out
}

/// Fire `source.advisory` findings for any pinned action whose resolved
/// version falls inside the vulnerable range of a published repo advisory.
///
/// Tag-pinned and SHA-pinned actions are both eligible. SHAs are resolved
/// to a tag via the GitHub tags endpoint; if no matching tag exists in the
/// first page (100), the action is silently skipped — the alternative
/// would be either over-flagging or making this rule O(repo) per scan,
/// and neither is justifiable for an MVP.
///
/// Sliding-tag refs (`@v4`) and branch refs are not version-precise, so
/// no advisory matching is attempted — those refs already trigger
/// `pin.sliding` / `pin.branch`.
async fn enrich_with_source_advisory(
    report: &mut ScoreReport,
    repo_root: &Path,
    client: &GitHubClient,
) -> Result<()> {
    let files = workflow::find_workflows(repo_root)?;

    let mut occurrences: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
    // action_ref -> (owner, repo, ref_string, ref_type)
    let mut action_pins: BTreeMap<String, (String, String, String, RefType)> = BTreeMap::new();

    for file in &files {
        let display = workflow::display_path(file, repo_root);
        let content = std::fs::read_to_string(file)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
        for a in workflow::scan_content(&content) {
            let action_ref = format!("{}@{}", a.full_name(), a.ref_string);
            action_pins.entry(action_ref.clone()).or_insert((
                a.owner.clone(),
                a.repo.clone(),
                a.ref_string.clone(),
                a.ref_type.clone(),
            ));
            occurrences.entry(action_ref).or_default().push(Occurrence {
                workflow: display.clone(),
                line: a.line_number,
            });
        }
    }

    // Resolve each pin to a concrete tag string. SHAs cost one tag lookup
    // per unique (owner, repo, sha); tags resolve trivially to themselves.
    let mut action_resolved: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    let mut sha_tag_cache: BTreeMap<(String, String, String), Option<String>> = BTreeMap::new();
    for (action_ref, (owner, repo, ref_string, ref_type)) in &action_pins {
        let resolved = match ref_type {
            RefType::Sha => {
                let key = (owner.clone(), repo.clone(), ref_string.clone());
                if let Some(cached) = sha_tag_cache.get(&key) {
                    cached.clone()
                } else {
                    let tag = match client.sha_to_tag(owner, repo, ref_string).await {
                        Ok(t) => t,
                        Err(e) if is_hard_github_error(&e) => {
                            warn_enrichment_incomplete("source.advisory", &e);
                            return Ok(());
                        }
                        Err(_) => None,
                    };
                    sha_tag_cache.insert(key, tag.clone());
                    tag
                }
            }
            RefType::Tag => Some(ref_string.clone()),
            RefType::SlidingTag | RefType::Branch => None,
        };
        if let Some(tag) = resolved {
            action_resolved.insert(action_ref.clone(), (owner.clone(), repo.clone(), tag));
        }
    }

    // Pull advisories once per (owner, repo) that has at least one resolved pin.
    let mut advisories: BTreeMap<(String, String), Vec<SecurityAdvisory>> = BTreeMap::new();
    for (owner, repo, _) in action_resolved.values() {
        let key = (owner.clone(), repo.clone());
        if advisories.contains_key(&key) {
            continue;
        }
        let advs = match client.list_security_advisories(owner, repo).await {
            Ok(advs) => advs,
            Err(e) if is_hard_github_error(&e) => {
                warn_enrichment_incomplete("source.advisory", &e);
                return Ok(());
            }
            Err(_) => Vec::new(),
        };
        advisories.insert(key, advs);
    }

    let new_findings = advisory_findings(&action_resolved, &advisories, &occurrences);
    if !new_findings.is_empty() {
        report.findings.extend(new_findings);
        recompute_score(report);
    }
    Ok(())
}

/// Pure helper: emit `source.advisory` findings for any action whose
/// resolved tag falls inside one of the vulnerable version ranges of a
/// repo advisory. Extracted from `enrich_with_source_advisory` so the
/// version-matching logic can be unit-tested against fixture data.
fn advisory_findings(
    action_resolved: &BTreeMap<String, (String, String, String)>,
    advisories: &BTreeMap<(String, String), Vec<SecurityAdvisory>>,
    occurrences: &BTreeMap<String, Vec<Occurrence>>,
) -> Vec<Finding> {
    let rule = RuleId::SourceAdvisory;
    let mut out = Vec::new();
    for (action_ref, (owner, repo, tag)) in action_resolved {
        let Some(repo_advs) = advisories.get(&(owner.clone(), repo.clone())) else {
            continue;
        };
        for adv in repo_advs {
            let Some((matched_range, patched)) = adv.vulnerabilities.iter().find_map(|v| {
                // Only the entry for THIS action's package — a co-listed package
                // (e.g. a CLI) can carry a range that false-matches the action.
                if !vuln_is_for_action(v, owner, repo) {
                    return None;
                }
                let range = v.vulnerable_version_range.as_deref()?;
                if version_in_range(tag, range).unwrap_or(false) {
                    Some((range.to_string(), v.patched_versions.clone()))
                } else {
                    None
                }
            }) else {
                continue;
            };
            let mut occs = occurrences.get(action_ref).cloned().unwrap_or_default();
            occs.sort_by(|a, b| a.workflow.cmp(&b.workflow).then(a.line.cmp(&b.line)));
            out.push(Finding {
                id: rule.id(),
                category: rule.category(),
                severity: rule.severity(),
                points: rule.points(),
                action_ref: Some(action_ref.clone()),
                occurrences: occs,
                remediation: rule.remediation(),
                details: Some(format_advisory_details(
                    adv,
                    &matched_range,
                    patched.as_deref(),
                )),
            });
        }
    }
    out
}

/// Build the per-finding `details` blob for a `source.advisory` match.
/// Includes severity, the vulnerable range we matched against, any
/// `patched_versions` hint, the summary (truncated), and a link to the
/// advisory.
fn format_advisory_details(
    adv: &SecurityAdvisory,
    matched_range: &str,
    patched: Option<&str>,
) -> String {
    let mut parts = vec![format!("{} ({})", adv.ghsa_id, adv.severity)];
    parts.push(format!("vulnerable: {matched_range}"));
    if let Some(p) = patched.filter(|s| !s.is_empty()) {
        parts.push(format!("patched: {p}"));
    }
    let summary = adv.summary.trim();
    if !summary.is_empty() {
        let truncated: String = if summary.chars().count() > 120 {
            let mut s: String = summary.chars().take(117).collect();
            s.push_str("...");
            s
        } else {
            summary.to_string()
        };
        parts.push(truncated);
    }
    parts.push(adv.html_url.clone());
    parts.join(" — ")
}

/// Decide whether `version` falls inside `range`, after normalizing the
/// `v` prefix that GitHub Actions tags and advisory ranges often carry.
/// Returns `None` if either string can't be parsed as semver — callers
/// treat that as "no match" rather than aborting the scan.
fn version_in_range(version: &str, range: &str) -> Option<bool> {
    let v = strip_v_prefix(version);
    let mut ver = semver::Version::parse(v).ok()?;
    // semver's VersionReq won't match a pre-release (`2.0.0-rc1`) unless the
    // comparator names one, so match on the numeric version only.
    ver.pre = semver::Prerelease::EMPTY;
    ver.build = semver::BuildMetadata::EMPTY;

    // GitHub uses `or` (union) and `and`/comma (intersection); semver has no
    // `or`, so match if any `or`-clause holds. None only if nothing parses.
    let mut parsed_any = false;
    for clause in range.split(" or ") {
        let clause = clause
            .trim()
            .trim_end_matches(',')
            .trim()
            .replace(" and ", ", ");
        let r = normalize_range_string(&clause);
        // A bare version (`1.2.3`) means exact, not semver's caret default.
        let r = if r.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
            format!("={}", r.trim())
        } else {
            r
        };
        if let Ok(req) = semver::VersionReq::parse(&r) {
            parsed_any = true;
            if req.matches(&ver) {
                return Some(true);
            }
        }
    }
    parsed_any.then_some(false)
}

/// True if this vulnerability entry is for the action being scored. An advisory
/// can list several packages (an action *and* a CLI); matching against another
/// package's range is a false positive. Actions packages are named `owner/repo`.
fn vuln_is_for_action(v: &AdvisoryVulnerability, owner: &str, repo: &str) -> bool {
    v.package
        .as_ref()
        .and_then(|p| p.name.as_deref())
        .is_some_and(|name| name.eq_ignore_ascii_case(&format!("{owner}/{repo}")))
}

fn strip_v_prefix(s: &str) -> &str {
    s.strip_prefix('v').unwrap_or(s)
}

/// Strip the `v` prefix from any version literal inside a semver range
/// string. GitHub advisories return ranges like `< v40.2.3` or
/// `>= v1.0.0, < v2.0.0`; the `semver` crate doesn't accept the prefix.
fn normalize_range_string(s: &str) -> String {
    static V_PREFIX_RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"(^|[\s,<>=!^~])v(\d)").unwrap());
    V_PREFIX_RE.replace_all(s, "$1$2").to_string()
}

/// Map an audit finding to the runtime.* rule it corresponds to. Pipe-to-shell
/// patterns get their own rule (higher weight) because the payload is never
/// written to disk and cannot be checksum-verified even after the fact; every
/// other runtime fetch is scored by severity.
fn runtime_rule_for(finding: &AuditFinding) -> RuleId {
    if is_pipe_to_shell_finding(finding) {
        return RuleId::RuntimePipeToShell;
    }
    match finding.severity.as_str() {
        "high" => RuleId::RuntimeFetchHigh,
        "medium" => RuleId::RuntimeFetchMedium,
        _ => RuleId::RuntimeFetchLow,
    }
}

/// Pipe-to-shell findings are identified by phrases unique to the four
/// patterns in `SHELL_PIPE_PATTERNS` (piped to shell, process substitution,
/// command substitution, Invoke-Expression). If those descriptions are ever
/// changed, this mapping breaks — the `runtime_pipe_to_shell_descriptions_are_stable`
/// test exists to catch that.
fn is_pipe_to_shell_finding(finding: &AuditFinding) -> bool {
    const MARKERS: &[&str] = &[
        "piped to shell",
        "process substitution",
        "command substitution",
        "Invoke-Expression on fetched content",
    ];
    MARKERS.iter().any(|m| finding.description.contains(m))
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
    let mut report = score_repo(repo_root, &config)?;

    // Rules that need the GitHub API run after the offline scan. Without a
    // token we silently skip them — same behavior as `audit`.
    if let Some(token) = auth::resolve_token().await {
        let client = GitHubClient::new(token);
        enrich_with_source_archived(&mut report, repo_root, &client).await?;
        enrich_with_source_advisory(&mut report, repo_root, &client).await?;
    }

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
            crate::output::sanitize_for_terminal(target).dimmed()
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
            RuleId::SourceAdvisory,
            RuleId::SourceArchived,
            RuleId::SourceUnverified,
            RuleId::RuntimePipeToShell,
            RuleId::RuntimeFetchHigh,
            RuleId::RuntimeFetchMedium,
            RuleId::RuntimeFetchLow,
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
    fn runtime_rules_fire_end_to_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let wfdir = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wfdir).unwrap();
        let yaml = r#"
name: risky
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: |
          curl -fsSL https://example.com/install.sh | bash
          wget https://github.com/owner/repo/releases/latest/download/tool
          git clone https://github.com/other/thing
          pip install requests
"#;
        std::fs::write(wfdir.join("risky.yml"), yaml).unwrap();

        let report = score_repo(dir.path(), &Config::default()).unwrap();
        let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"runtime.pipe_to_shell"), "ids: {ids:?}");
        assert!(ids.contains(&"runtime.fetch.high"), "ids: {ids:?}");
        assert!(ids.contains(&"runtime.fetch.medium"), "ids: {ids:?}");
        assert!(ids.contains(&"runtime.fetch.low"), "ids: {ids:?}");
        // 20 (pipe-to-shell) + 15 (wget latest) + 8 (git clone) + 3 (pip install) = 46
        assert_eq!(report.totals.points_deducted, 46);
        assert_eq!(report.score, 54);
        assert_eq!(report.grade, "F");
    }

    #[test]
    fn runtime_pipe_to_shell_descriptions_are_stable() {
        // If any of these descriptions change in audit_patterns.rs, the
        // `is_pipe_to_shell_finding` mapping silently degrades — pipe-to-shell
        // findings would get mapped to runtime.fetch.high (-15) instead of
        // runtime.pipe_to_shell (-20). This test catches that.
        use crate::audit_patterns::SHELL_PIPE_PATTERNS;
        for pattern in SHELL_PIPE_PATTERNS.iter() {
            let fake = AuditFinding {
                severity: "high".to_string(),
                category: "ShellFetch".to_string(),
                action: String::new(),
                source_file: String::new(),
                line: Some(1),
                pattern_matched: String::new(),
                description: pattern.description.to_string(),
                workflow_file: None,
                workflow_line: None,
            };
            assert!(
                is_pipe_to_shell_finding(&fake),
                "pipe-to-shell description no longer matched by is_pipe_to_shell_finding: {:?}",
                pattern.description
            );
        }
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

    fn make_adv(
        ghsa: &str,
        severity: &str,
        range: &str,
        patched: Option<&str>,
        summary: &str,
    ) -> SecurityAdvisory {
        SecurityAdvisory {
            ghsa_id: ghsa.to_string(),
            html_url: format!("https://github.com/owner/repo/security/advisories/{ghsa}"),
            severity: severity.to_string(),
            summary: summary.to_string(),
            vulnerabilities: vec![crate::github::AdvisoryVulnerability {
                package: Some(crate::github::AdvisoryPackage {
                    name: Some("owner/repo".to_string()),
                }),
                vulnerable_version_range: Some(range.to_string()),
                patched_versions: patched.map(|s| s.to_string()),
            }],
        }
    }

    #[test]
    fn version_in_range_handles_v_prefix() {
        // Tag pinned `v40.2.0`, advisory range `< v40.2.3` → vulnerable.
        assert_eq!(version_in_range("v40.2.0", "< v40.2.3"), Some(true));
        // Tag pinned `v45.0.7`, advisory range `<= 45.0.7` → still vulnerable.
        assert_eq!(version_in_range("v45.0.7", "<= 45.0.7"), Some(true));
        // Patched: tag `v45.0.8`, range `<= 45.0.7` → not vulnerable.
        assert_eq!(version_in_range("v45.0.8", "<= 45.0.7"), Some(false));
    }

    #[test]
    fn version_in_range_handles_compound_range() {
        assert_eq!(version_in_range("1.5.0", ">= 1.0.0, < 2.0.0"), Some(true));
        assert_eq!(version_in_range("2.0.0", ">= 1.0.0, < 2.0.0"), Some(false));
        assert_eq!(version_in_range("0.9.9", ">= 1.0.0, < 2.0.0"), Some(false));
    }

    #[test]
    fn version_in_range_unparsable_returns_none() {
        // Sliding tag like `v4` — not full semver. Don't crash, don't match.
        assert_eq!(version_in_range("v4", "< 4.2.3"), None);
        // Garbage in the range string.
        assert_eq!(version_in_range("1.2.3", "not a range"), None);
    }

    #[test]
    fn version_in_range_matches_prerelease_pins() {
        // A vulnerable pre-release pin must still match a release-version range;
        // semver's VersionReq would otherwise refuse to match the pre-release.
        assert_eq!(version_in_range("1.2.3-rc1", "< 2.0.0"), Some(true));
        assert_eq!(
            version_in_range("v1.9.0-beta", ">= 1.0.0, < 2.0.0"),
            Some(true)
        );
        // Past the patched version, even as a pre-release → not vulnerable.
        assert_eq!(version_in_range("2.1.0-rc1", "< 2.0.0"), Some(false));
    }

    #[test]
    fn version_in_range_treats_bare_version_as_exact() {
        // A comparator-less range is an exact match, not caret (`^1.2.3`).
        assert_eq!(version_in_range("1.2.3", "1.2.3"), Some(true));
        assert_eq!(version_in_range("1.9.0", "1.2.3"), Some(false));
        assert_eq!(version_in_range("v2.0.0", "v2.0.0"), Some(true));
    }

    #[test]
    fn version_in_range_handles_github_and_or_syntax() {
        // GitHub's union/intersection range form (as returned for GHSA-vqf5).
        let range = ">= 3.26.11 and <= 3.28.2, or >= 2.26.11 and < 3";
        // A current major (v4) is in neither clause.
        assert_eq!(version_in_range("4.35.5", range), Some(false));
        // Inside the second clause (`>= 2.26.11 and < 3`).
        assert_eq!(version_in_range("2.27.0", range), Some(true));
        // Inside the first clause (`>= 3.26.11 and <= 3.28.2`).
        assert_eq!(version_in_range("3.27.0", range), Some(true));
        // Between the two clauses → not vulnerable.
        assert_eq!(version_in_range("3.28.3", range), Some(false));
    }

    #[test]
    fn is_hard_github_error_only_for_auth_and_rate_limit() {
        assert!(is_hard_github_error(&anyhow::Error::new(
            GitHubError::AuthRequired
        )));
        assert!(is_hard_github_error(&anyhow::Error::new(
            GitHubError::RateLimit
        )));
        assert!(!is_hard_github_error(&anyhow::Error::new(
            GitHubError::RepoNotFound {
                owner: "o".into(),
                repo: "r".into(),
            }
        )));
        assert!(!is_hard_github_error(&anyhow::anyhow!("network blip")));
    }

    #[test]
    fn recompute_score_orders_same_action_advisories_by_details() {
        let finding = |details: &str| Finding {
            id: "source.advisory",
            category: Category::Source,
            severity: Severity::High,
            points: 15,
            action_ref: Some("owner/repo@v1.0.0".to_string()),
            occurrences: vec![],
            remediation: "",
            details: Some(details.to_string()),
        };
        let mut report = ScoreReport {
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
                workflows_scanned: 1,
                unique_actions: 1,
            },
            // Inserted in reverse-sorted details order; same id/points/action_ref.
            findings: vec![finding("GHSA-bbbb"), finding("GHSA-aaaa")],
        };
        recompute_score(&mut report);
        assert_eq!(report.findings[0].details.as_deref(), Some("GHSA-aaaa"));
        assert_eq!(report.findings[1].details.as_deref(), Some("GHSA-bbbb"));
    }

    #[test]
    fn normalize_range_string_strips_v_prefix_only_on_version_literals() {
        assert_eq!(normalize_range_string("< v40.2.3"), "< 40.2.3");
        assert_eq!(
            normalize_range_string(">= v1.0.0, < v2.0.0"),
            ">= 1.0.0, < 2.0.0"
        );
        // Leading `v` at start of string also stripped.
        assert_eq!(normalize_range_string("v1.2.3"), "1.2.3");
        // No-op on already-clean ranges.
        assert_eq!(normalize_range_string("<= 45.0.7"), "<= 45.0.7");
    }

    #[test]
    fn advisory_findings_emits_per_match_with_details() {
        let mut action_resolved = BTreeMap::new();
        action_resolved.insert(
            "owner/repo@SHA".to_string(),
            (
                "owner".to_string(),
                "repo".to_string(),
                "v1.5.0".to_string(),
            ),
        );
        let mut advisories = BTreeMap::new();
        advisories.insert(
            ("owner".to_string(), "repo".to_string()),
            vec![make_adv(
                "GHSA-xxxx-yyyy-zzzz",
                "high",
                "< 2.0.0",
                Some(">= 2.0.0"),
                "Auth bypass in owner/repo",
            )],
        );
        let mut occurrences = BTreeMap::new();
        occurrences.insert(
            "owner/repo@SHA".to_string(),
            vec![Occurrence {
                workflow: ".github/workflows/ci.yml".to_string(),
                line: 7,
            }],
        );

        let findings = advisory_findings(&action_resolved, &advisories, &occurrences);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "source.advisory");
        assert_eq!(findings[0].points, 15);
        let details = findings[0].details.as_deref().unwrap();
        assert!(details.contains("GHSA-xxxx-yyyy-zzzz"));
        assert!(details.contains("vulnerable: < 2.0.0"));
        assert!(details.contains("patched: >= 2.0.0"));
        assert!(details.contains("Auth bypass"));
        assert!(details.contains("https://github.com/owner/repo/security/advisories/"));
    }

    #[test]
    fn advisory_findings_skips_non_matching_versions() {
        let mut action_resolved = BTreeMap::new();
        action_resolved.insert(
            "owner/repo@SHA".to_string(),
            (
                "owner".to_string(),
                "repo".to_string(),
                "v3.0.0".to_string(),
            ),
        );
        let mut advisories = BTreeMap::new();
        advisories.insert(
            ("owner".to_string(), "repo".to_string()),
            vec![make_adv("GHSA-aaaa", "high", "< 2.0.0", None, "old bug")],
        );
        let occurrences = BTreeMap::new();
        let findings = advisory_findings(&action_resolved, &advisories, &occurrences);
        assert!(findings.is_empty());
    }

    #[test]
    fn advisory_findings_emits_one_per_advisory_when_multiple_match() {
        // Two advisories both cover this version → two findings.
        let mut action_resolved = BTreeMap::new();
        action_resolved.insert(
            "owner/repo@SHA".to_string(),
            (
                "owner".to_string(),
                "repo".to_string(),
                "v1.0.0".to_string(),
            ),
        );
        let mut advisories = BTreeMap::new();
        advisories.insert(
            ("owner".to_string(), "repo".to_string()),
            vec![
                make_adv("GHSA-aaaa", "high", "<= 1.0.0", None, "first"),
                make_adv("GHSA-bbbb", "high", "< 2.0.0", None, "second"),
            ],
        );
        let occurrences = BTreeMap::new();
        let findings = advisory_findings(&action_resolved, &advisories, &occurrences);
        assert_eq!(findings.len(), 2);
        let ghsa_ids: Vec<&str> = findings
            .iter()
            .map(|f| f.details.as_deref().unwrap())
            .collect();
        assert!(ghsa_ids.iter().any(|d| d.contains("GHSA-aaaa")));
        assert!(ghsa_ids.iter().any(|d| d.contains("GHSA-bbbb")));
    }

    #[test]
    fn advisory_findings_skips_repo_with_no_advisories() {
        let mut action_resolved = BTreeMap::new();
        action_resolved.insert(
            "owner/repo@SHA".to_string(),
            (
                "owner".to_string(),
                "repo".to_string(),
                "v1.0.0".to_string(),
            ),
        );
        let advisories = BTreeMap::new();
        let occurrences = BTreeMap::new();
        let findings = advisory_findings(&action_resolved, &advisories, &occurrences);
        assert!(findings.is_empty());
    }

    #[test]
    fn advisory_findings_ignores_other_packages_in_advisory() {
        // Regression for the codeql-action false positive: GHSA-vqf5 lists both
        // `github/codeql-action` and the `CodeQL CLI`. The CLI's open-ended
        // `>= 2.9.2` must not match the action's v4 pin, and the action's own
        // range (GitHub `and`/`or` syntax) excludes v4 too → zero findings.
        let mut action_resolved = BTreeMap::new();
        action_resolved.insert(
            "github/codeql-action@SHA".to_string(),
            (
                "github".to_string(),
                "codeql-action".to_string(),
                "v4.35.5".to_string(),
            ),
        );
        let adv = SecurityAdvisory {
            ghsa_id: "GHSA-vqf5-2xx6-9wfm".to_string(),
            html_url: "https://github.com/github/codeql-action/security/advisories/GHSA-vqf5"
                .to_string(),
            severity: "high".to_string(),
            summary: "PAT written to debug artifacts".to_string(),
            vulnerabilities: vec![
                crate::github::AdvisoryVulnerability {
                    package: Some(crate::github::AdvisoryPackage {
                        name: Some("github/codeql-action".to_string()),
                    }),
                    vulnerable_version_range: Some(
                        ">= 3.26.11 and <= 3.28.2, or >= 2.26.11 and < 3".to_string(),
                    ),
                    patched_versions: None,
                },
                crate::github::AdvisoryVulnerability {
                    package: Some(crate::github::AdvisoryPackage {
                        name: Some("CodeQL CLI".to_string()),
                    }),
                    vulnerable_version_range: Some(">= 2.9.2".to_string()),
                    patched_versions: None,
                },
            ],
        };
        let mut advisories = BTreeMap::new();
        advisories.insert(
            ("github".to_string(), "codeql-action".to_string()),
            vec![adv],
        );
        let occurrences = BTreeMap::new();
        let findings = advisory_findings(&action_resolved, &advisories, &occurrences);
        assert!(
            findings.is_empty(),
            "a patched v4 action must not match a v2-era advisory or a co-listed package"
        );
    }

    #[test]
    fn advisory_findings_matches_action_via_github_range_syntax() {
        // The same advisory DOES flag a genuinely-vulnerable action version
        // expressed in GitHub's `and`/`or` syntax (the second clause).
        let mut action_resolved = BTreeMap::new();
        action_resolved.insert(
            "github/codeql-action@SHA".to_string(),
            (
                "github".to_string(),
                "codeql-action".to_string(),
                "v2.27.0".to_string(),
            ),
        );
        let adv = SecurityAdvisory {
            ghsa_id: "GHSA-vqf5-2xx6-9wfm".to_string(),
            html_url: "https://example.test/adv".to_string(),
            severity: "high".to_string(),
            summary: "x".to_string(),
            vulnerabilities: vec![crate::github::AdvisoryVulnerability {
                package: Some(crate::github::AdvisoryPackage {
                    name: Some("github/codeql-action".to_string()),
                }),
                vulnerable_version_range: Some(
                    ">= 3.26.11 and <= 3.28.2, or >= 2.26.11 and < 3".to_string(),
                ),
                patched_versions: None,
            }],
        };
        let mut advisories = BTreeMap::new();
        advisories.insert(
            ("github".to_string(), "codeql-action".to_string()),
            vec![adv],
        );
        let occurrences = BTreeMap::new();
        let findings = advisory_findings(&action_resolved, &advisories, &occurrences);
        assert_eq!(findings.len(), 1, "v2.27.0 is inside `>= 2.26.11 and < 3`");
    }

    #[test]
    fn format_advisory_details_truncates_long_summary() {
        let long = "x".repeat(500);
        let adv = make_adv("GHSA-cccc", "high", "< 1.0.0", None, &long);
        let details = format_advisory_details(&adv, "< 1.0.0", None);
        // 117 chars + ellipsis, not the full 500.
        assert!(details.contains("..."));
        assert!(!details.contains(&"x".repeat(500)));
    }

    #[test]
    fn source_advisory_rule_metadata() {
        let rule = RuleId::SourceAdvisory;
        assert_eq!(rule.id(), "source.advisory");
        assert_eq!(rule.category(), Category::Source);
        assert_eq!(rule.severity(), Severity::High);
        assert_eq!(rule.points(), 15);
        assert!(rule.remediation().contains("vulnerable"));
    }

    #[test]
    fn source_archived_rule_metadata() {
        // The rubric in docs/scoring.md is the contract: high, 10 points,
        // category Source, id "source.archived". If any of these drift,
        // re-derivability of scores from the public rubric breaks.
        let rule = RuleId::SourceArchived;
        assert_eq!(rule.id(), "source.archived");
        assert_eq!(rule.category(), Category::Source);
        assert_eq!(rule.severity(), Severity::High);
        assert_eq!(rule.points(), 10);
        assert!(rule.remediation().contains("maintained"));
    }

    #[test]
    fn archived_findings_skips_non_archived_repos() {
        let mut action_repo = BTreeMap::new();
        action_repo.insert(
            "alive/action@v1".to_string(),
            ("alive".to_string(), "action".to_string()),
        );
        action_repo.insert(
            "dead/action@v1".to_string(),
            ("dead".to_string(), "action".to_string()),
        );

        let mut archived = BTreeMap::new();
        archived.insert(("alive".to_string(), "action".to_string()), false);
        archived.insert(("dead".to_string(), "action".to_string()), true);

        let mut occurrences = BTreeMap::new();
        occurrences.insert(
            "dead/action@v1".to_string(),
            vec![Occurrence {
                workflow: ".github/workflows/ci.yml".to_string(),
                line: 12,
            }],
        );

        let findings = archived_findings(&action_repo, &archived, &occurrences);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "source.archived");
        assert_eq!(findings[0].action_ref.as_deref(), Some("dead/action@v1"));
        assert_eq!(findings[0].points, 10);
        assert_eq!(findings[0].occurrences.len(), 1);
    }

    #[test]
    fn archived_findings_sorts_occurrences_by_workflow_then_line() {
        let mut action_repo = BTreeMap::new();
        action_repo.insert(
            "dead/action@v1".to_string(),
            ("dead".to_string(), "action".to_string()),
        );
        let mut archived = BTreeMap::new();
        archived.insert(("dead".to_string(), "action".to_string()), true);

        // Intentionally inserted out of order — b.yml line 30, a.yml line 20,
        // a.yml line 10. Expected order: a.yml:10, a.yml:20, b.yml:30.
        let mut occurrences = BTreeMap::new();
        occurrences.insert(
            "dead/action@v1".to_string(),
            vec![
                Occurrence {
                    workflow: ".github/workflows/b.yml".to_string(),
                    line: 30,
                },
                Occurrence {
                    workflow: ".github/workflows/a.yml".to_string(),
                    line: 20,
                },
                Occurrence {
                    workflow: ".github/workflows/a.yml".to_string(),
                    line: 10,
                },
            ],
        );

        let findings = archived_findings(&action_repo, &archived, &occurrences);
        let occs = &findings[0].occurrences;
        assert_eq!(occs[0].workflow, ".github/workflows/a.yml");
        assert_eq!(occs[0].line, 10);
        assert_eq!(occs[1].workflow, ".github/workflows/a.yml");
        assert_eq!(occs[1].line, 20);
        assert_eq!(occs[2].workflow, ".github/workflows/b.yml");
        assert_eq!(occs[2].line, 30);
    }

    #[test]
    fn archived_findings_handles_missing_archived_entry() {
        // An action_ref whose (owner, repo) isn't in the archived map at all
        // (e.g., GitHub returned an error and we never cached a result) is
        // treated as not archived — same behavior as `archived == Some(&false)`.
        let mut action_repo = BTreeMap::new();
        action_repo.insert(
            "mystery/action@v1".to_string(),
            ("mystery".to_string(), "action".to_string()),
        );
        let archived = BTreeMap::new();
        let occurrences = BTreeMap::new();
        let findings = archived_findings(&action_repo, &archived, &occurrences);
        assert!(findings.is_empty());
    }

    #[test]
    fn archived_findings_empty_when_nothing_archived() {
        let action_repo = BTreeMap::new();
        let archived = BTreeMap::new();
        let occurrences = BTreeMap::new();
        let findings = archived_findings(&action_repo, &archived, &occurrences);
        assert!(findings.is_empty());
    }

    #[test]
    fn recompute_score_sorts_and_updates_totals() {
        let mut report = ScoreReport {
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
                workflows_scanned: 1,
                unique_actions: 2,
            },
            findings: vec![
                // Intentionally inserted out of order to verify the sort.
                Finding {
                    id: "pin.sliding",
                    category: Category::Pin,
                    severity: Severity::Medium,
                    points: 5,
                    action_ref: Some("actions/checkout@v4".to_string()),
                    occurrences: vec![],
                    remediation: "",
                    details: None,
                },
                Finding {
                    id: "source.archived",
                    category: Category::Source,
                    severity: Severity::High,
                    points: 10,
                    action_ref: Some("dead/action@v1".to_string()),
                    occurrences: vec![],
                    remediation: "",
                    details: None,
                },
            ],
        };
        recompute_score(&mut report);
        // 10 deducted before 5; total = 15; score = 85; grade = B.
        assert_eq!(report.findings[0].id, "source.archived");
        assert_eq!(report.findings[1].id, "pin.sliding");
        assert_eq!(report.totals.points_deducted, 15);
        assert_eq!(report.totals.findings, 2);
        assert_eq!(report.score, 85);
        assert_eq!(report.grade, "B");
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
                details: None,
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
                details: None,
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
                    details: None,
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
                    details: None,
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
                    details: None,
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

    mod enrichment {
        use super::*;
        use serde_json::json;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Write a single workflow pinning `o/r` at a 40-char SHA tagged v1.0.0,
        /// then produce the offline base report the enrichers extend.
        fn base_report(dir: &std::path::Path) -> ScoreReport {
            let wfdir = dir.join(".github").join("workflows");
            std::fs::create_dir_all(&wfdir).unwrap();
            let sha = "a".repeat(40);
            let yaml = format!(
                "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/r@{sha} # v1.0.0\n"
            );
            std::fs::write(wfdir.join("ci.yml"), yaml).unwrap();
            score_repo(dir, &Config::default()).unwrap()
        }

        #[tokio::test]
        async fn source_archived_fires_when_repo_is_archived() {
            let dir = tempfile::TempDir::new().unwrap();
            let mut report = base_report(dir.path());

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "archived": true })))
                .mount(&server)
                .await;
            let client = GitHubClient::with_base("t".into(), server.uri());

            enrich_with_source_archived(&mut report, dir.path(), &client)
                .await
                .unwrap();
            assert!(report.findings.iter().any(|f| f.id == "source.archived"));
        }

        #[tokio::test]
        async fn source_advisory_fires_when_pin_is_in_vulnerable_range() {
            let dir = tempfile::TempDir::new().unwrap();
            let mut report = base_report(dir.path());

            let server = MockServer::start().await;
            // The SHA pin resolves to v1.0.0 via the tags endpoint...
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v1.0.0", "commit": { "sha": "a".repeat(40) } }
                ])))
                .mount(&server)
                .await;
            // ...which falls inside this advisory's vulnerable range.
            Mock::given(method("GET"))
                .and(path("/repos/o/r/security-advisories"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "ghsa_id": "GHSA-test",
                        "html_url": "https://github.com/advisories/GHSA-test",
                        "severity": "high",
                        "summary": "vulnerable",
                        "vulnerabilities": [
                            {
                                "package": { "name": "o/r" },
                                "vulnerable_version_range": "< 1.1.0",
                                "patched_versions": "1.1.0"
                            }
                        ]
                    }
                ])))
                .mount(&server)
                .await;
            let client = GitHubClient::with_base("t".into(), server.uri());

            enrich_with_source_advisory(&mut report, dir.path(), &client)
                .await
                .unwrap();
            assert!(report.findings.iter().any(|f| f.id == "source.advisory"));
        }

        #[tokio::test]
        async fn source_advisory_skips_when_package_does_not_match() {
            let dir = tempfile::TempDir::new().unwrap();
            let mut report = base_report(dir.path());

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repos/o/r/tags"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "name": "v1.0.0", "commit": { "sha": "a".repeat(40) } }
                ])))
                .mount(&server)
                .await;
            // Advisory range covers v1.0.0 but is for a *co-listed* package, not
            // the action — the #216 false-match guard must keep this silent.
            Mock::given(method("GET"))
                .and(path("/repos/o/r/security-advisories"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "ghsa_id": "GHSA-other",
                        "html_url": "https://github.com/advisories/GHSA-other",
                        "severity": "high",
                        "summary": "different package",
                        "vulnerabilities": [
                            {
                                "package": { "name": "o/some-cli" },
                                "vulnerable_version_range": "< 1.1.0",
                                "patched_versions": "1.1.0"
                            }
                        ]
                    }
                ])))
                .mount(&server)
                .await;
            let client = GitHubClient::with_base("t".into(), server.uri());

            enrich_with_source_advisory(&mut report, dir.path(), &client)
                .await
                .unwrap();
            assert!(!report.findings.iter().any(|f| f.id == "source.advisory"));
        }
    }
}
