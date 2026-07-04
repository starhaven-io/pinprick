use anyhow::{Result, bail};

pub async fn resolve_token() -> Option<String> {
    // A set-but-empty token variable (common in CI) counts as absent — fall
    // through to the next source. GH_TOKEN is the variable the gh CLI itself
    // honors, so check it before shelling out to gh.
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(token) = std::env::var(var)
            && !token.is_empty()
        {
            return Some(token);
        }
    }

    let output = tokio::process::Command::new("gh")
        .args(["auth", "token"])
        .output()
        .await
        .ok()?;

    if output.status.success() {
        let token = String::from_utf8(output.stdout).ok()?.trim().to_string();
        if !token.is_empty() {
            return Some(token);
        }
    }

    None
}

pub async fn require_token() -> Result<String> {
    match resolve_token().await {
        Some(token) => Ok(token),
        None => bail!(
            "No GitHub token found.\n\
             Set GITHUB_TOKEN or run `gh auth login` first."
        ),
    }
}
