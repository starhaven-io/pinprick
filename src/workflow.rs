use anyhow::{Context, Result};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct ActionRef {
    pub owner: String,
    pub repo: String,
    pub subpath: Option<String>,
    pub ref_string: String,
    pub ref_type: RefType,
    pub tag_comment: Option<String>,
    pub line_number: usize,
    /// The full original line text
    pub raw_line: String,
}

impl ActionRef {
    pub fn full_name(&self) -> String {
        match &self.subpath {
            Some(sub) => format!("{}/{}/{}", self.owner, self.repo, sub),
            None => format!("{}/{}", self.owner, self.repo),
        }
    }

    pub fn owner_repo(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RefType {
    Branch,
    Sha,
    SlidingTag,
    Tag,
}

static USES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\s*-?\s*uses:\s*)([^\s@]+)@(\S+?)(\s*#\s*(.+?))?\s*$").unwrap()
});

static RUN_BLOCK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\s*)(?:-\s+)?run\s*:\s*[|>][0-9+\-]*\s*$").unwrap());

/// Parse a single line into an ActionRef, if it's a `uses:` line with an external action.
pub fn parse_uses_line(line: &str, line_number: usize) -> Option<ActionRef> {
    let caps = USES_RE.captures(line)?;

    let action_path = caps.get(2)?.as_str();
    let ref_string = caps.get(3)?.as_str().to_string();
    let tag_comment = caps.get(5).map(|m| m.as_str().trim().to_string());

    if action_path.starts_with('.') {
        return None;
    }

    // Parse owner/repo[/subpath]
    let parts: Vec<&str> = action_path.splitn(3, '/').collect();
    if parts.len() < 2 {
        return None;
    }

    let owner = parts[0].to_string();
    let repo = parts[1].to_string();
    let subpath = if parts.len() == 3 {
        Some(parts[2].to_string())
    } else {
        None
    };

    let ref_type = classify_ref(&ref_string);

    Some(ActionRef {
        owner,
        repo,
        subpath,
        ref_string,
        ref_type,
        tag_comment,
        line_number,
        raw_line: line.to_string(),
    })
}

fn classify_ref(r: &str) -> RefType {
    if r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()) {
        return RefType::Sha;
    }

    let version_part = r.strip_prefix('v').unwrap_or(r);
    if !version_part.is_empty() && version_part.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return if version_part.contains('.') {
            RefType::Tag
        } else {
            RefType::SlidingTag
        };
    }

    RefType::Branch
}

/// Build a replacement line: same prefix, new SHA, tag as comment.
pub fn build_pinned_line(line: &str, sha: &str, original_tag: &str) -> Option<String> {
    let caps = USES_RE.captures(line)?;
    let prefix = caps.get(1)?.as_str();
    let action_path = caps.get(2)?.as_str();
    Some(format!("{prefix}{action_path}@{sha} # {original_tag}"))
}

/// Scan workflow YAML text and return all external action references.
///
/// Lines inside `run:` block scalars are skipped so that shell heredocs and
/// inline scripts can't false-match on literal `- uses:` text (e.g. a workflow
/// that generates a test workflow on the fly).
pub fn scan_content(content: &str) -> Vec<ActionRef> {
    let mut refs = Vec::new();
    let mut block_parent_col: Option<usize> = None;

    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;

        if let Some(start_col) = block_parent_col {
            let indent = line.chars().take_while(|c| *c == ' ').count();
            if line.trim().is_empty() || indent > start_col {
                continue;
            }
            block_parent_col = None;
        }

        if let Some(caps) = RUN_BLOCK_RE.captures(line) {
            block_parent_col = Some(caps.get(1).unwrap().as_str().len());
            continue;
        }

        if let Some(r) = parse_uses_line(line, line_num) {
            refs.push(r);
        }
    }

    refs
}

/// Scan a workflow file and return all external action references.
pub fn scan_workflow(path: &Path) -> Result<Vec<ActionRef>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(scan_content(&content))
}

/// Find all workflow files in a repository.
pub fn find_workflows(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let workflows_dir = repo_root.join(".github").join("workflows");
    if !workflows_dir.is_dir() {
        anyhow::bail!(
            "No .github/workflows/ directory found in {}",
            repo_root.display()
        );
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&workflows_dir)
        .with_context(|| format!("reading {}", workflows_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension()
            && (ext == "yml" || ext == "yaml")
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_uses_line ─────────────────────────────────────────────────

    #[test]
    fn parse_sliding_tag() {
        let r = parse_uses_line("      - uses: actions/checkout@v4", 1).unwrap();
        assert_eq!(r.owner, "actions");
        assert_eq!(r.repo, "checkout");
        assert_eq!(r.ref_string, "v4");
        assert_eq!(r.ref_type, RefType::SlidingTag);
        assert!(r.subpath.is_none());
        assert!(r.tag_comment.is_none());
    }

    #[test]
    fn parse_exact_tag() {
        let r = parse_uses_line("      - uses: actions/checkout@v4.3.1", 1).unwrap();
        assert_eq!(r.ref_type, RefType::Tag);
    }

    #[test]
    fn parse_sha_ref_with_tag_comment() {
        let line =
            "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2";
        let r = parse_uses_line(line, 5).unwrap();
        assert_eq!(r.ref_type, RefType::Sha);
        assert_eq!(r.tag_comment.as_deref(), Some("v6.0.2"));
        assert_eq!(r.line_number, 5);
    }

    #[test]
    fn parse_branch_ref() {
        let r = parse_uses_line("      - uses: Homebrew/actions/setup-homebrew@main", 1).unwrap();
        assert_eq!(r.ref_type, RefType::Branch);
        assert_eq!(r.owner, "Homebrew");
        assert_eq!(r.repo, "actions");
        assert_eq!(r.subpath.as_deref(), Some("setup-homebrew"));
    }

    #[test]
    fn parse_subpath_action() {
        let r =
            parse_uses_line("        uses: github/codeql-action/init@abc123def456abc123def456abc123def456abcd # v4.35.1", 1)
                .unwrap();
        assert_eq!(r.owner, "github");
        assert_eq!(r.repo, "codeql-action");
        assert_eq!(r.subpath.as_deref(), Some("init"));
        assert_eq!(r.full_name(), "github/codeql-action/init");
    }

    #[test]
    fn parse_numeric_sliding_tag() {
        let r = parse_uses_line("      - uses: some/action@4", 1).unwrap();
        assert_eq!(r.ref_type, RefType::SlidingTag);
    }

    #[test]
    fn parse_numeric_exact_tag() {
        let r = parse_uses_line("      - uses: some/action@4.1", 1).unwrap();
        assert_eq!(r.ref_type, RefType::Tag);
    }

    #[test]
    fn skip_local_action() {
        assert!(parse_uses_line("      - uses: ./.github/actions/my-action@v1", 1).is_none());
    }

    #[test]
    fn skip_non_uses_line() {
        assert!(parse_uses_line("      - run: echo hello", 1).is_none());
        assert!(parse_uses_line("name: CI", 1).is_none());
        assert!(parse_uses_line("", 1).is_none());
    }

    #[test]
    fn preserves_raw_line() {
        let line = "      - uses: actions/checkout@v4";
        let r = parse_uses_line(line, 1).unwrap();
        assert_eq!(r.raw_line, line);
    }

    // ── build_pinned_line ───────────────────────────────────────────────

    #[test]
    fn pin_simple_tag() {
        let line = "      - uses: actions/checkout@v4";
        let result = build_pinned_line(line, "abc123def456", "v4").unwrap();
        assert_eq!(result, "      - uses: actions/checkout@abc123def456 # v4");
    }

    #[test]
    fn pin_replaces_existing_comment() {
        let line = "      - uses: actions/checkout@v3 # old comment";
        let result = build_pinned_line(line, "abc123", "v4").unwrap();
        assert_eq!(result, "      - uses: actions/checkout@abc123 # v4");
    }

    #[test]
    fn pin_preserves_indentation() {
        let line = "        uses: actions/checkout@v4";
        let result = build_pinned_line(line, "sha123", "v4").unwrap();
        assert!(result.starts_with("        uses:"));
    }

    #[test]
    fn pin_with_subpath() {
        let line = "      - uses: github/codeql-action/init@v3";
        let result = build_pinned_line(line, "sha123", "v3").unwrap();
        assert_eq!(
            result,
            "      - uses: github/codeql-action/init@sha123 # v3"
        );
    }

    // ── full_name / owner_repo ──────────────────────────────────────────

    #[test]
    fn full_name_without_subpath() {
        let r = parse_uses_line("      - uses: actions/checkout@v4", 1).unwrap();
        assert_eq!(r.full_name(), "actions/checkout");
        assert_eq!(r.owner_repo(), "actions/checkout");
    }

    #[test]
    fn full_name_with_subpath() {
        let r = parse_uses_line("      - uses: github/codeql-action/init@v3", 1).unwrap();
        assert_eq!(r.full_name(), "github/codeql-action/init");
        assert_eq!(r.owner_repo(), "github/codeql-action");
    }

    // ── scan_content: block scalar skipping ─────────────────────────────

    #[test]
    fn scan_skips_uses_inside_run_block() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate workflow
        run: |
          cat > test.yml <<YAML
          steps:
            - uses: ${OWNER}/${REPO}@${SHA}
          YAML
      - uses: actions/setup-node@v4
"#;
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].full_name(), "actions/checkout");
        assert_eq!(refs[1].full_name(), "actions/setup-node");
    }

    #[test]
    fn scan_handles_block_scalar_chomping_indicators() {
        // `|`, `|-`, `|+`, `>`, `>-`, `>+`, `|2`, etc. — all should trigger skip mode.
        for marker in ["|", "|-", "|+", ">", ">-", ">+", "|2", "|2-", ">-2"] {
            let yaml = format!(
                "steps:\n  - run: {marker}\n      - uses: evil/action@v1\n  - uses: good/action@v2\n"
            );
            let refs = scan_content(&yaml);
            assert_eq!(
                refs.len(),
                1,
                "marker {marker:?} should skip the inner uses"
            );
            assert_eq!(refs[0].full_name(), "good/action");
        }
    }

    #[test]
    fn scan_inline_run_does_not_trigger_skip() {
        // `run: echo foo` (no block scalar marker) is a flow scalar — don't skip.
        let yaml = "steps:\n  - run: echo hello\n  - uses: actions/checkout@v4\n";
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "actions/checkout");
    }

    #[test]
    fn scan_handles_blank_lines_inside_run_block() {
        let yaml =
            "steps:\n  - run: |\n      echo one\n\n      echo two\n  - uses: actions/checkout@v4\n";
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "actions/checkout");
    }

    #[test]
    fn scan_exits_block_scalar_on_dedent() {
        let yaml = "steps:\n  - run: |\n      echo shell\n  - uses: real/action@v1\n";
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "real/action");
    }

    #[test]
    fn scan_multiple_run_blocks_in_one_file() {
        let yaml = r#"
jobs:
  a:
    steps:
      - run: |
          echo uses: fake/a@v1
      - uses: real/a@v1
  b:
    steps:
      - run: |
          echo uses: fake/b@v1
      - uses: real/b@v1
"#;
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].full_name(), "real/a");
        assert_eq!(refs[1].full_name(), "real/b");
    }

    // ── classify_ref edge cases ────────────────────────────────────────

    #[test]
    fn classify_39_hex_chars_is_branch() {
        let short = "a".repeat(39);
        assert!(matches!(classify_ref(&short), RefType::Branch));
    }

    #[test]
    fn classify_41_hex_chars_is_branch() {
        let long = "a".repeat(41);
        assert!(matches!(classify_ref(&long), RefType::Branch));
    }

    #[test]
    fn classify_40_hex_chars_is_sha() {
        let sha = "a".repeat(40);
        assert!(matches!(classify_ref(&sha), RefType::Sha));
    }

    #[test]
    fn classify_mixed_case_hex_is_sha() {
        let sha = "aAbBcCdDeEfF0011223344556677889900112233";
        assert!(matches!(classify_ref(sha), RefType::Sha));
    }

    #[test]
    fn classify_prerelease_tag_is_branch() {
        assert!(matches!(classify_ref("v1.2.3-alpha"), RefType::Branch));
    }

    #[test]
    fn classify_main_is_branch() {
        assert!(matches!(classify_ref("main"), RefType::Branch));
    }

    // ── build_pinned_line ──────────────────────────────────────────────

    #[test]
    fn build_pinned_line_non_uses_returns_none() {
        assert!(build_pinned_line("  - run: echo hello", "abc123", "v1").is_none());
    }

    // ── display_path ───────────────────────────────────────────────────

    #[test]
    fn display_path_relative() {
        let root = Path::new("/repo");
        let path = Path::new("/repo/.github/workflows/ci.yml");
        assert_eq!(display_path(path, root), ".github/workflows/ci.yml");
    }

    #[test]
    fn display_path_outside_root() {
        let root = Path::new("/repo");
        let path = Path::new("/other/ci.yml");
        assert_eq!(display_path(path, root), "/other/ci.yml");
    }

    // ── rewrite_actions ────────────────────────────────────────────────

    #[test]
    fn rewrite_preserves_trailing_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.yml");
        std::fs::write(&file, "line1\nline2\n").unwrap();
        let count = rewrite_actions(&file, &[(1, "replaced".to_string())]).unwrap();
        assert_eq!(count, 1);
        let result = std::fs::read_to_string(&file).unwrap();
        assert!(result.ends_with('\n'));
        assert_eq!(result, "replaced\nline2\n");
    }

    #[test]
    fn rewrite_no_trailing_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.yml");
        std::fs::write(&file, "line1\nline2").unwrap();
        let count = rewrite_actions(&file, &[(1, "replaced".to_string())]).unwrap();
        assert_eq!(count, 1);
        let result = std::fs::read_to_string(&file).unwrap();
        assert!(!result.ends_with('\n'));
    }

    #[test]
    fn rewrite_out_of_bounds_skipped() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.yml");
        std::fs::write(&file, "line1\n").unwrap();
        let count = rewrite_actions(&file, &[(99, "nope".to_string())]).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn rewrite_empty_replacements() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.yml");
        std::fs::write(&file, "line1\n").unwrap();
        let count = rewrite_actions(&file, &[]).unwrap();
        assert_eq!(count, 0);
    }
}

/// Format a file path relative to the repo root for display.
pub fn display_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Rewrite action references in a file. Returns the number of replacements made.
pub fn rewrite_actions(
    path: &Path,
    replacements: &[(usize, String)], // (line_number, new_line)
) -> Result<usize> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let mut count = 0;

    for (line_num, new_line) in replacements {
        let idx = line_num - 1; // 1-based to 0-based
        if idx < lines.len() {
            lines[idx] = new_line.clone();
            count += 1;
        }
    }

    // Preserve trailing newline if original had one
    let mut output = lines.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }

    std::fs::write(path, &output).with_context(|| format!("writing {}", path.display()))?;
    Ok(count)
}
