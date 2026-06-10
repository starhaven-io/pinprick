mod audit;
mod audit_patterns;
mod audited_actions;
mod auth;
mod config;
mod github;
mod output;
mod pin;
mod score;
mod update;
mod workflow;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::control;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum ColorMode {
    Always,
    Auto,
    Never,
}

#[derive(Parser)]
#[command(
    name = "pinprick",
    about = "GitHub Actions supply chain security",
    version,
    propagate_version = true
)]
struct Cli {
    /// When to use colors
    #[arg(long, default_value = "auto", global = true)]
    color: ColorMode,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Audit actions for runtime fetch risks
    Audit {
        /// Repository root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show every matched outbound-call pattern, including ones that
        /// passed the version check (useful for CI audit logs)
        #[arg(short, long)]
        verbose: bool,

        /// Output findings as SARIF 2.1.0 (for github/codeql-action/upload-sarif)
        #[arg(long)]
        sarif: bool,

        /// Ignore the scanned repository's .pinprick.toml and use the global
        /// config (or defaults) — for auditing repositories you don't control
        #[arg(long)]
        no_repo_config: bool,
    },
    /// Remove locally cached audit results
    Clean,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
    /// Pin action references to full SHAs
    Pin {
        /// Repository root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Write changes to files (default is dry-run)
        #[arg(long = "write")]
        apply: bool,
    },
    /// Score a repository's Actions supply chain posture
    Score {
        /// Repository root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Emit a self-contained HTML report to stdout (mutually exclusive
        /// with --json)
        #[arg(long)]
        html: bool,

        /// Ignore the scanned repository's .pinprick.toml and use the global
        /// config (or defaults) — for scoring repositories you don't control
        #[arg(long)]
        no_repo_config: bool,
    },
    /// Check for updates to pinned actions
    Update {
        /// Repository root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Write changes to files (default is dry-run)
        #[arg(long = "write")]
        apply: bool,

        /// Only check actions whose owner/repo contains this substring
        /// (e.g., `actions/checkout`, `actions/` for the whole org)
        #[arg(long, value_name = "PATTERN")]
        only: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.color {
        ColorMode::Always => control::set_override(true),
        ColorMode::Never => control::set_override(false),
        ColorMode::Auto => {}
    }

    // clap can't enforce these conflicts: --json is a global arg on the parent
    // command, and conflicts_with does not reach across the subcommand boundary.
    let conflicting_flag = match &cli.command {
        Command::Audit { sarif: true, .. } if cli.json => Some("--sarif"),
        Command::Score { html: true, .. } if cli.json => Some("--html"),
        _ => None,
    };
    if let Some(flag) = conflicting_flag {
        // --json is necessarily set for either conflict to fire.
        let err = serde_json::json!({ "error": format!("{flag} cannot be combined with --json") });
        eprintln!("{err}");
        return ExitCode::from(2);
    }

    let result = match &cli.command {
        Command::Audit {
            path,
            verbose,
            sarif,
            no_repo_config,
        } => {
            let config = config::Config::load(path, !no_repo_config);
            audit::run(path, cli.json, *sarif, *verbose, &config).await
        }
        Command::Clean => {
            let removed = match audited_actions::cache_dir() {
                Some(dir) if dir.is_dir() => std::fs::remove_dir_all(&dir).is_ok(),
                _ => false,
            };

            if cli.json {
                let msg = serde_json::json!({ "cleaned": removed });
                println!("{msg}");
            } else if removed {
                println!("Cache cleaned.");
            } else {
                println!("Nothing to clean.");
            }
            return ExitCode::SUCCESS;
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "pinprick",
                &mut std::io::stdout(),
            );
            return ExitCode::SUCCESS;
        }
        Command::Pin { path, apply } => pin::run(path, cli.json, *apply).await,
        Command::Score {
            path,
            html,
            no_repo_config,
        } => score::run(path, cli.json, *html, *no_repo_config).await,
        Command::Update { path, apply, only } => {
            update::run(path, *apply, cli.json, only.as_deref()).await
        }
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            if cli.json {
                let err = serde_json::json!({ "error": format!("{e:#}") });
                eprintln!("{err}");
            } else {
                eprintln!("error: {e:#}");
            }
            ExitCode::from(2)
        }
    }
}
