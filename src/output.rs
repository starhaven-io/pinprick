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
        println!(
            "Pinned {} action{} across {} file{}{}",
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
                "--apply".bold()
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
}

#[derive(Serialize)]
pub struct AuditReport {
    pub findings: Vec<AuditFinding>,
    pub actions_scanned: usize,
    pub had_token: bool,
}

impl AuditReport {
    pub fn print_human(&self) {
        if self.findings.is_empty() {
            println!("No runtime fetch risks found.");
            if !self.had_token {
                println!(
                    "{}",
                    "Note: no GitHub token available — only local workflow run: blocks were scanned."
                        .dimmed()
                );
            }
            return;
        }

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

        if !self.had_token {
            println!(
                "{}",
                "Note: no GitHub token — action source code was not scanned.".dimmed()
            );
        }
    }

    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }
}

pub fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}
