mod audit;
mod audit_patterns;
mod audited_actions;
mod auth;
mod config;
mod github;
mod output;
mod pin;
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
    /// When to use colors: auto, always, never
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
        #[arg(long, conflicts_with = "json")]
        sarif: bool,
    },
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

        /// Preview changes without writing files. Exits 1 when there are
        /// unpinned actions — useful for CI gating.
        #[arg(long)]
        dry_run: bool,
    },
    /// Check for updates to pinned actions
    Update {
        /// Repository root
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Apply updates (default is dry-run)
        #[arg(long)]
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

    let result = match &cli.command {
        Command::Audit {
            path,
            verbose,
            sarif,
        } => {
            let config = config::Config::load(path);
            audit::run(path, cli.json, *sarif, *verbose, &config).await
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
        Command::Pin { path, dry_run } => pin::run(path, cli.json, *dry_run).await,
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
