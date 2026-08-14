use anyhow::{Context, Result};
use regex::Regex;
use rustix::fs::{self as rfs, AtFlags, Dir, Mode, OFlags};
use rustix::io::Errno;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ActionRef {
    pub owner: String,
    pub repo: String,
    pub subpath: Option<String>,
    pub ref_string: String,
    pub ref_type: RefType,
    pub tag_comment: Option<String>,
    pub line_number: usize,
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

static LOCAL_USES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*-?\s*uses:\s*(?:"([^"]+)"|'([^']+)'|([^#\s]+))\s*(?:#.*)?$"#).unwrap()
});

static DOCKER_USES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*-?\s*uses:\s*(?:"docker://([^"]+)"|'docker://([^']+)'|docker://([^#\s]+))\s*(?:#.*)?$"#,
    )
    .unwrap()
});

// YAML block scalar openers (`run: |`, `script: >`, etc.), including
// indent/chomping indicators (`|2-`, `>+`). Every block body is skipped so
// literal docs or scripts cannot false-match on `uses:` text.
static BLOCK_SCALAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"^(\s*)(?:"#,
        r#"(?:-\s+)?(?:[A-Za-z0-9_-]+|\"(?:[^\"\\]|\\.)*\"|'[^']*')\s*:\s*"#,
        r#"(?:(?:&[^\s]+|![^\s]+)\s+)*"#,
        r#"|-\s+(?:(?:&[^\s]+|![^\s]+)\s+)*"#,
        r#")[|>][0-9+\-]*\s*(?:#.*)?$"#,
    ))
    .unwrap()
});

#[derive(Debug, Clone)]
pub struct LocalActionRef {
    pub path: String,
    pub line_number: usize,
}

/// A container action reference: `uses: docker://image[:tag][@sha256:digest]`.
#[derive(Debug, Clone)]
pub struct DockerRef {
    /// The image reference as written, without the `docker://` scheme
    /// (e.g. `alpine:3.20`, `ghcr.io/owner/image@sha256:…`).
    pub image: String,
    pub pin: DockerPin,
    pub line_number: usize,
    pub raw_line: String,
}

impl DockerRef {
    pub fn uses_ref(&self) -> String {
        format!("docker://{}", self.image)
    }
}

/// How a container image reference is pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerPin {
    /// `@sha256:<64 hex>` digest — immutable, the container analog of a SHA pin.
    Digest,
    /// A named tag other than `latest` (e.g. `:3.20`) — mutable; the registry
    /// can re-push different content under the same tag.
    Tag,
    /// `:latest` or no tag at all — tracks whatever the registry currently
    /// serves, the container analog of a branch ref.
    Latest,
}

/// Parse a single line into a container action reference
/// (`uses: docker://…`), if any.
pub fn parse_docker_uses_line(line: &str, line_number: usize) -> Option<DockerRef> {
    let caps = DOCKER_USES_RE.captures(line)?;
    let image = caps
        .get(1)
        .or_else(|| caps.get(2))
        .or_else(|| caps.get(3))?
        .as_str();
    if image.is_empty() {
        return None;
    }

    Some(DockerRef {
        image: image.to_string(),
        pin: classify_docker_image(image),
        line_number,
        raw_line: line.to_string(),
    })
}

fn classify_docker_image(image: &str) -> DockerPin {
    // `image@sha256:<hex>` — only a well-formed digest counts as pinned; a
    // malformed one would not resolve, and must not read as pinned.
    if let Some((_, digest)) = image.split_once('@') {
        if let Some(hex) = digest.strip_prefix("sha256:")
            && hex.len() == 64
            && hex.chars().all(|c| c.is_ascii_hexdigit())
        {
            return DockerPin::Digest;
        }
        return DockerPin::Latest;
    }

    // The tag separator is a `:` after the last `/` — a colon before that is
    // a registry port (`registry:5000/image`), not a tag.
    let name_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[name_start..].split_once(':') {
        Some((_, tag)) if !tag.is_empty() && tag != "latest" => DockerPin::Tag,
        _ => DockerPin::Latest,
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct UnsafeWorkflowPath {
    message: String,
}

impl UnsafeWorkflowPath {
    fn symlinked_directory(path: &Path) -> Self {
        Self {
            message: format!("Refusing to scan symlinked directory {}", path.display()),
        }
    }

    fn symlinked_workflow_file(path: &Path) -> Self {
        Self {
            message: format!(
                "Refusing to scan symlinked workflow file {}",
                path.display()
            ),
        }
    }

    fn symlinked_file(path: &Path) -> Self {
        Self {
            message: format!("Refusing to scan symlinked file {}", path.display()),
        }
    }
}

pub fn is_unsafe_workflow_path(err: &anyhow::Error) -> bool {
    err.downcast_ref::<UnsafeWorkflowPath>().is_some()
}

#[derive(Debug)]
struct WorkflowDirectory {
    path: PathBuf,
    fd: Arc<File>,
}

#[derive(Debug, Clone)]
pub struct WorkflowFile {
    path: PathBuf,
    name: std::ffi::OsString,
    dir: Arc<File>,
}

impl WorkflowDirectory {
    fn file(&self, name: std::ffi::OsString) -> WorkflowFile {
        WorkflowFile {
            path: self.path.join(&name),
            name,
            dir: Arc::clone(&self.fd),
        }
    }
}

impl WorkflowFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Parse a single line into an ActionRef, if it's a `uses:` line with an external action.
pub fn parse_uses_line(line: &str, line_number: usize) -> Option<ActionRef> {
    let caps = USES_RE.captures(line)?;

    let mut action_path = caps.get(2)?.as_str();
    let mut ref_string = caps.get(3)?.as_str().to_string();
    let tag_comment = caps.get(5).map(|m| m.as_str().trim().to_string());

    // Strip a matched surrounding quote pair: `uses: "owner/repo@v4"` puts the
    // quotes on the path and ref, which would break classification.
    for q in ['"', '\''] {
        if action_path.starts_with(q) && ref_string.ends_with(q) {
            action_path = &action_path[1..];
            ref_string.pop();
            break;
        }
    }

    if action_path.starts_with('.') {
        return None;
    }

    // `docker://image@sha256:…` is a container reference, not a GitHub repo —
    // parsing it here would misread `docker:` as an owner and a digest-pinned
    // image as an unpinned branch ref. Container refs are handled by
    // `parse_docker_uses_line` instead.
    if action_path.contains("://") {
        return None;
    }

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

/// Parse a single line into a local action reference (`uses: ./path`), if any.
pub fn parse_local_uses_line(line: &str, line_number: usize) -> Option<LocalActionRef> {
    let caps = LOCAL_USES_RE.captures(line)?;
    let path = caps
        .get(1)
        .or_else(|| caps.get(2))
        .or_else(|| caps.get(3))?
        .as_str();

    if !path.starts_with("./") || !is_safe_local_action_path(path) {
        return None;
    }

    Some(LocalActionRef {
        path: path.to_string(),
        line_number,
    })
}

fn is_safe_local_action_path(path: &str) -> bool {
    let Some(rel) = path.strip_prefix("./") else {
        return false;
    };
    !rel.is_empty()
        && Path::new(rel)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
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
    let ref_str = caps.get(3)?.as_str();

    // Keep a surrounding quote pair so `uses: "owner/repo@v4"` stays valid; the
    // comment goes after the closing quote.
    if let Some(q) = action_path
        .chars()
        .next()
        .filter(|c| *c == '"' || *c == '\'')
        && ref_str.ends_with(q)
    {
        let inner = &action_path[1..];
        return Some(format!("{prefix}{q}{inner}@{sha}{q} # {original_tag}"));
    }
    Some(format!("{prefix}{action_path}@{sha} # {original_tag}"))
}

/// Iterate the scannable lines of workflow YAML as `(1-based line number,
/// line)`, skipping the bodies of block scalars so that shell heredocs, inline
/// docs, and `with: script: |` snippets can't false-match on literal
/// `- uses:` text.
fn scannable_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut block_parent_col: Option<usize> = None;

    content.lines().enumerate().filter_map(move |(i, line)| {
        if let Some(start_col) = block_parent_col {
            let indent = line.chars().take_while(|c| *c == ' ').count();
            if line.trim().is_empty() || indent > start_col {
                return None;
            }
            block_parent_col = None;
        }

        if let Some(caps) = BLOCK_SCALAR_RE.captures(line) {
            block_parent_col = Some(caps.get(1).unwrap().as_str().len());
            return None;
        }

        Some((i + 1, line))
    })
}

/// Scan workflow YAML text and return all external action references.
pub fn scan_content(content: &str) -> Vec<ActionRef> {
    scannable_lines(content)
        .filter_map(|(line_num, line)| parse_uses_line(line, line_num))
        .collect()
}

/// Scan workflow YAML text and return local action references (`uses: ./path`).
///
/// Only references in the workflow itself are returned. A composite action that
/// references another local action from its own `action.yml` is not followed —
/// such a nested action is scanned only if a workflow also uses it directly.
pub fn scan_local_actions(content: &str) -> Vec<LocalActionRef> {
    scannable_lines(content)
        .filter_map(|(line_num, line)| parse_local_uses_line(line, line_num))
        .collect()
}

/// Scan workflow YAML text and return container action references
/// (`uses: docker://…`).
pub fn scan_docker_refs(content: &str) -> Vec<DockerRef> {
    scannable_lines(content)
        .filter_map(|(line_num, line)| parse_docker_uses_line(line, line_num))
        .collect()
}

/// Scan a workflow file and return all external action references.
pub fn scan_workflow(file: &WorkflowFile) -> Result<Vec<ActionRef>> {
    let content = read_workflow(file)?;
    Ok(scan_content(&content))
}

pub fn read_workflow(file: &WorkflowFile) -> Result<String> {
    let mut handle = open_workflow_file(file)?;
    let mut content = String::new();
    handle
        .read_to_string(&mut content)
        .with_context(|| format!("reading {}", file.path.display()))?;
    Ok(content)
}

/// Forge roots scanned for a `workflows/` subdirectory. GitHub (`.github`),
/// Forgejo (`.forgejo`), and Gitea (`.gitea`) all use byte-compatible workflow
/// syntax, so the same `uses:`/`run:` scanning applies to each.
///
/// This list is a compile-time constant on purpose: the scanned repository's
/// `.pinprick.toml` cannot influence it. Discovery is purely additive: every
/// root that exists is scanned and the results are unioned, so a hostile repo
/// can never redirect the scan to a decoy directory while real workflows hide
/// in another. Extra roots can only widen coverage, never narrow it.
///
/// GitHub Actions is the first-class target; Forgejo/Gitea support is
/// incidental to GHA compatibility and best-effort.
pub const DEFAULT_FORGE_ROOTS: &[&str] = &[".github", ".forgejo", ".gitea"];

/// Find all workflow files in a repository, scanning every default forge root.
pub fn find_workflows(repo_root: &Path) -> Result<Vec<WorkflowFile>> {
    find_workflows_in(repo_root, DEFAULT_FORGE_ROOTS)
}

/// Find all workflow files under the given forge roots (e.g. `.github`,
/// `.forgejo`). Each `<root>/workflows/` directory that exists is scanned and
/// the files are merged and sorted. It is an error for *none* of the roots to
/// contain a `workflows/` directory.
fn find_workflows_in(repo_root: &Path, forge_roots: &[&str]) -> Result<Vec<WorkflowFile>> {
    let dirs = open_workflows_dirs(repo_root, forge_roots)?;

    let mut files = Vec::new();
    for workflows in &dirs {
        let entries = Dir::read_from(&*workflows.fd)
            .with_context(|| format!("reading {}", workflows.path.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", workflows.path.display()))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = std::ffi::OsStr::from_bytes(name).to_os_string();
            let file = workflows.file(name);
            if !is_workflow_file(file.path()) {
                continue;
            }

            let file_type = workflow_entry_type(workflows, &file)?;
            if file_type.is_symlink() {
                return Err(UnsafeWorkflowPath::symlinked_workflow_file(file.path()).into());
            }
            if file_type.is_file() {
                files.push(file);
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// Open the `workflows/` directory under each existing forge root. Roots that
/// are absent are silently skipped; a root present but symlinked is refused
/// loudly (it is never followed). Bails if no root yields a `workflows/`
/// directory.
fn open_workflows_dirs(repo_root: &Path, forge_roots: &[&str]) -> Result<Vec<WorkflowDirectory>> {
    let root = open_repo_root(repo_root)?;
    let mut dirs = Vec::new();
    for forge in forge_roots {
        let forge_path = repo_root.join(forge);
        let Some(forge_dir) = open_child_dir(&root, forge, &forge_path)? else {
            continue;
        };
        let workflows_path = forge_path.join("workflows");
        let Some(workflows) = open_child_dir(&forge_dir, "workflows", &workflows_path)? else {
            continue;
        };
        dirs.push(WorkflowDirectory {
            path: workflows_path,
            fd: Arc::new(workflows),
        });
    }

    if dirs.is_empty() {
        let looked_for = forge_roots
            .iter()
            .map(|r| format!("{r}/workflows/"))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "No workflow directory found in {} (looked for {looked_for})",
            repo_root.display()
        );
    }

    Ok(dirs)
}

pub fn open_child_dir_path(repo_root: &Path, rel: &Path) -> Result<Option<File>> {
    let mut current = open_repo_root(repo_root)?;
    let mut display_path = repo_root.to_path_buf();

    for component in rel.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("child path escapes the repository");
        };
        let Some(name) = name.to_str() else {
            anyhow::bail!("child path contains non-UTF-8 components");
        };
        display_path.push(name);
        let Some(next) = open_child_dir(&current, name, &display_path)? else {
            return Ok(None);
        };
        current = next;
    }

    Ok(Some(current))
}

pub fn open_child_file_path(repo_root: &Path, rel: &Path) -> Result<Option<File>> {
    let mut current = open_repo_root(repo_root)?;
    let mut display_path = repo_root.to_path_buf();
    let mut components = rel.components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            anyhow::bail!("child path escapes the repository");
        };
        let Some(name) = name.to_str() else {
            anyhow::bail!("child path contains non-UTF-8 components");
        };
        display_path.push(name);

        if components.peek().is_some() {
            let Some(next) = open_child_dir(&current, name, &display_path)? else {
                return Ok(None);
            };
            current = next;
            continue;
        }

        let file = match openat_file(
            &current,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        ) {
            Ok(file) => file,
            Err(e) if e == Errno::LOOP || path_is_symlink(&display_path) => {
                return Err(UnsafeWorkflowPath::symlinked_file(&display_path).into());
            }
            Err(e) if e == Errno::NOENT || e == Errno::NOTDIR => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| format!("checking {}", display_path.display()));
            }
        };
        return Ok(file.metadata()?.file_type().is_file().then_some(file));
    }

    Ok(None)
}

fn open_repo_root(repo_root: &Path) -> Result<File> {
    openat_file(
        rfs::CWD,
        repo_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
    )
    .with_context(|| format!("checking {}", repo_root.display()))
}

fn open_child_dir(parent: &File, name: &str, path: &Path) -> Result<Option<File>> {
    match openat_file(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e == Errno::LOOP || path_is_symlink(path) => {
            Err(UnsafeWorkflowPath::symlinked_directory(path).into())
        }
        Err(e) if e == Errno::NOENT || e == Errno::NOTDIR => Ok(None),
        Err(e) => Err(e).with_context(|| format!("checking {}", path.display())),
    }
}

fn path_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or_default()
}

fn open_workflow_file(file: &WorkflowFile) -> Result<File> {
    match openat_file(
        &*file.dir,
        file.name.as_os_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
    ) {
        Ok(handle) => Ok(handle),
        Err(e) if e == Errno::LOOP => {
            Err(UnsafeWorkflowPath::symlinked_workflow_file(file.path()).into())
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", file.path.display())),
    }
}

fn workflow_entry_type(
    workflows: &WorkflowDirectory,
    file: &WorkflowFile,
) -> Result<rfs::FileType> {
    let stat = rfs::statat(
        &*workflows.fd,
        file.name.as_os_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .with_context(|| format!("checking {}", file.path.display()))?;
    Ok(rfs::FileType::from_raw_mode(stat.st_mode))
}

fn openat_file<Fd: rustix::fd::AsFd, P: rustix::path::Arg>(
    dirfd: Fd,
    path: P,
    flags: OFlags,
) -> std::result::Result<File, Errno> {
    rfs::openat(dirfd, path, flags, Mode::empty()).map(File::from)
}

fn create_openat_file<Fd: rustix::fd::AsFd, P: rustix::path::Arg>(
    dirfd: Fd,
    path: P,
    flags: OFlags,
) -> std::result::Result<File, Errno> {
    rfs::openat(dirfd, path, flags, Mode::from_raw_mode(0o666)).map(File::from)
}

fn is_workflow_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext == "yml" || ext == "yaml")
}

/// Format a file path relative to the repo root for display.
pub fn display_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Rewrite action references in a file. Returns the number of replacements made.
///
/// Each entry contains the line number, the line observed during scanning, and
/// its replacement. The observed line must still match when the file is
/// rewritten. Line numbers must be unique — a `uses:` line maps to a single
/// action. In debug builds a duplicate trips an assertion; in release it is
/// silently skipped so a caller bug can't corrupt a workflow by letting the
/// later entry clobber the earlier one.
pub fn rewrite_actions(
    file: &WorkflowFile,
    replacements: &[(usize, String, String)],
) -> Result<usize> {
    // Read content and mode from the same nofollow handle so a path swap cannot
    // mix one file's contents with another file's permissions.
    let mut source = open_workflow_file(file)?;
    let permissions = source
        .metadata()
        .with_context(|| format!("reading permissions for {}", file.path.display()))?
        .permissions();
    let mut content = String::new();
    source
        .read_to_string(&mut content)
        .with_context(|| format!("reading {}", file.path.display()))?;

    // Preserve CRLF: `str::lines()` strips `\r`, so we'd otherwise rewrite the
    // whole file to LF.
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let mut seen: std::collections::HashSet<usize> =
        std::collections::HashSet::with_capacity(replacements.len());
    let mut count = 0;

    for (line_num, expected_line, new_line) in replacements {
        if !seen.insert(*line_num) {
            debug_assert!(
                false,
                "duplicate rewrite target for line {line_num} in {}",
                file.path.display()
            );
            continue;
        }
        let Some(idx) = line_num.checked_sub(1) else {
            anyhow::bail!(
                "refusing to rewrite {}: invalid line number 0; rerun pinprick",
                file.path.display()
            );
        };
        let Some(current_line) = lines.get_mut(idx) else {
            anyhow::bail!(
                "refusing to rewrite {}: line {line_num} no longer exists; rerun pinprick",
                file.path.display()
            );
        };
        if current_line != expected_line {
            anyhow::bail!(
                "refusing to rewrite {}: line {line_num} changed since it was scanned; rerun pinprick",
                file.path.display()
            );
        }
        *current_line = new_line.clone();
        count += 1;
    }

    let mut output = lines.join(newline);
    if content.ends_with('\n') {
        output.push_str(newline);
    }

    // Write to a create-new sibling temp file and rename over the original so a
    // crash or full disk mid-write can't leave a truncated workflow behind.
    let file_name = file.name.as_os_str();
    let (tmp, mut tmp_file) = create_rewrite_temp(file, file_name)?;
    if let Err(e) = tmp_file.write_all(output.as_bytes()) {
        let _ = remove_workflow_tmp(file, &tmp);
        return Err(e).with_context(|| format!("writing {}", tmp_path(file, &tmp).display()));
    }
    if let Err(e) = tmp_file.set_permissions(permissions) {
        let _ = remove_workflow_tmp(file, &tmp);
        return Err(e).with_context(|| {
            format!(
                "preserving permissions on {}",
                tmp_path(file, &tmp).display()
            )
        });
    }
    drop(tmp_file);

    if let Err(e) = rfs::renameat(
        &*file.dir,
        tmp.as_os_str(),
        &*file.dir,
        file.name.as_os_str(),
    ) {
        let _ = remove_workflow_tmp(file, &tmp);
        return Err(e).with_context(|| format!("replacing {}", file.path.display()));
    }
    Ok(count)
}

fn create_rewrite_temp(
    file: &WorkflowFile,
    file_name: &std::ffi::OsStr,
) -> Result<(std::ffi::OsString, File)> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();

    for attempt in 0..100 {
        let tmp = std::ffi::OsString::from(format!(
            ".{}.pinprick-tmp-{pid}-{nonce}-{attempt}",
            file_name.to_string_lossy()
        ));
        match create_openat_file(
            &*file.dir,
            tmp.as_os_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        ) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e == Errno::EXIST => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("creating {}", tmp_path(file, &tmp).display()));
            }
        }
    }

    anyhow::bail!(
        "could not create a unique temporary workflow file next to {}",
        file.path.display()
    )
}

fn remove_workflow_tmp(
    file: &WorkflowFile,
    tmp: &std::ffi::OsStr,
) -> std::result::Result<(), Errno> {
    rfs::unlinkat(&*file.dir, tmp, AtFlags::empty())
}

fn tmp_path(file: &WorkflowFile, tmp: &std::ffi::OsStr) -> PathBuf {
    file.path.with_file_name(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workflow_path(root: &Path, name: &str) -> PathBuf {
        root.join(".github").join("workflows").join(name)
    }

    fn write_temp_workflow(dir: &tempfile::TempDir, name: &str, content: &str) -> WorkflowFile {
        let path = workflow_path(dir.path(), name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        find_workflows(dir.path())
            .unwrap()
            .into_iter()
            .find(|file| file.path() == path)
            .unwrap()
    }

    // ── parse_uses_line ─────────────────────────────────────────────────

    #[test]
    fn parse_docker_ref_skipped() {
        // A digest-pinned container reference is not a GitHub action and must
        // not be misread as owner `docker:` with a branch ref.
        assert!(parse_uses_line("      - uses: docker://alpine:3.20@sha256:abc123", 1).is_none());
        assert!(parse_uses_line("      - uses: docker://ghcr.io/owner/image:v1", 1).is_none());
    }

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
    fn parse_double_quoted_uses_ref() {
        let r = parse_uses_line("      - uses: \"actions/checkout@v4\"", 1).unwrap();
        assert_eq!(r.owner, "actions");
        assert_eq!(r.repo, "checkout");
        assert_eq!(r.ref_string, "v4");
        assert_eq!(r.ref_type, RefType::SlidingTag);
    }

    #[test]
    fn parse_single_quoted_uses_ref_with_comment() {
        let r = parse_uses_line("      - uses: 'actions/checkout@v4.2.1' # pinned", 1).unwrap();
        assert_eq!(r.owner, "actions");
        assert_eq!(r.ref_string, "v4.2.1");
        assert_eq!(r.ref_type, RefType::Tag);
        assert_eq!(r.tag_comment.as_deref(), Some("pinned"));
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

    // ── parse_docker_uses_line ──────────────────────────────────────────

    #[test]
    fn parse_docker_digest_pinned() {
        let digest = "a".repeat(64);
        let line = format!("      - uses: docker://ghcr.io/owner/image:v1@sha256:{digest}");
        let r = parse_docker_uses_line(&line, 3).unwrap();
        assert_eq!(r.pin, DockerPin::Digest);
        assert_eq!(r.image, format!("ghcr.io/owner/image:v1@sha256:{digest}"));
        assert_eq!(r.uses_ref(), format!("docker://{}", r.image));
        assert_eq!(r.line_number, 3);
    }

    #[test]
    fn parse_docker_malformed_digest_is_not_pinned() {
        // A digest that isn't 64 hex chars can't resolve — it must not read
        // as pinned.
        let r = parse_docker_uses_line("      - uses: docker://alpine@sha256:abc123", 1).unwrap();
        assert_eq!(r.pin, DockerPin::Latest);
        let r = parse_docker_uses_line("      - uses: docker://alpine@md5:abcd", 1).unwrap();
        assert_eq!(r.pin, DockerPin::Latest);
    }

    #[test]
    fn parse_docker_named_tag() {
        let r = parse_docker_uses_line("      - uses: docker://alpine:3.20", 1).unwrap();
        assert_eq!(r.pin, DockerPin::Tag);
        assert_eq!(r.image, "alpine:3.20");
    }

    #[test]
    fn parse_docker_latest_and_untagged() {
        for line in [
            "      - uses: docker://alpine:latest",
            "      - uses: docker://alpine",
            "      - uses: docker://ghcr.io/owner/image",
        ] {
            let r = parse_docker_uses_line(line, 1).unwrap();
            assert_eq!(r.pin, DockerPin::Latest, "line {line:?}");
        }
    }

    #[test]
    fn parse_docker_registry_port_is_not_a_tag() {
        // The colon before the last `/` is a registry port, not a tag.
        let r =
            parse_docker_uses_line("      - uses: docker://registry:5000/team/tool", 1).unwrap();
        assert_eq!(r.pin, DockerPin::Latest);
        let r = parse_docker_uses_line("      - uses: docker://registry:5000/team/tool:2.1", 1)
            .unwrap();
        assert_eq!(r.pin, DockerPin::Tag);
    }

    #[test]
    fn parse_docker_quoted_with_comment() {
        let r = parse_docker_uses_line("      - uses: \"docker://alpine:3.20\" # pinned-ish", 1)
            .unwrap();
        assert_eq!(r.pin, DockerPin::Tag);
        let r = parse_docker_uses_line("      - uses: 'docker://alpine:latest'", 1).unwrap();
        assert_eq!(r.pin, DockerPin::Latest);
    }

    #[test]
    fn parse_docker_ignores_non_docker_lines() {
        assert!(parse_docker_uses_line("      - uses: actions/checkout@v4", 1).is_none());
        assert!(parse_docker_uses_line("      - uses: ./local/action", 1).is_none());
        assert!(parse_docker_uses_line("      - run: docker://alpine", 1).is_none());
    }

    #[test]
    fn scan_docker_refs_skips_block_scalars() {
        let yaml = "\
jobs:
  test:
    steps:
      - run: |
          echo uses: docker://fake:latest
      - uses: docker://real:latest
";
        let refs = scan_docker_refs(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].image, "real:latest");
        assert_eq!(refs[0].line_number, 6);
    }

    #[test]
    fn parse_local_action() {
        let r = parse_local_uses_line("      - uses: ./.github/actions/my-action", 7).unwrap();
        assert_eq!(r.path, "./.github/actions/my-action");
        assert_eq!(r.line_number, 7);
    }

    #[test]
    fn parse_quoted_local_action_with_comment() {
        let r = parse_local_uses_line("      - uses: \"./.github/actions/my-action\" # local", 7)
            .unwrap();
        assert_eq!(r.path, "./.github/actions/my-action");
    }

    #[test]
    fn local_action_rejects_parent_escape() {
        assert!(parse_local_uses_line("      - uses: ../actions/my-action", 1).is_none());
        assert!(parse_local_uses_line("      - uses: ./../actions/my-action", 1).is_none());
    }

    #[test]
    fn skip_non_uses_line() {
        assert!(parse_uses_line("      - run: echo hello", 1).is_none());
        assert!(parse_uses_line("name: CI", 1).is_none());
        assert!(parse_uses_line("", 1).is_none());
        assert!(parse_uses_line("      - uses: checkout@v4", 1).is_none());
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

    #[test]
    fn pin_preserves_surrounding_quotes() {
        let line = "      - uses: \"actions/checkout@v4\"";
        let result = build_pinned_line(line, "abc123", "v4").unwrap();
        assert_eq!(result, "      - uses: \"actions/checkout@abc123\" # v4");
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
    fn scan_skips_extended_block_scalar_openers() {
        for opener in [
            "- |",
            "- &script |",
            "- !!str >",
            "- run: &script |",
            "- run: !!str >",
            "- run: &script !!str |",
            "- run: !!str &script >",
            "- \"run\": |",
            "- 'run': >",
            "- \"ru\\\"n\": | # quoted key",
        ] {
            let yaml = format!(
                "steps:\n  {opener}\n      - uses: evil/action@v1\n      - uses: ./fake\n  - uses: good/action@v2\n  - uses: ./real\n"
            );
            let refs = scan_content(&yaml);
            assert_eq!(
                refs.len(),
                1,
                "opener {opener:?} should hide external uses in its body"
            );
            assert_eq!(refs[0].full_name(), "good/action");

            let local = scan_local_actions(&yaml);
            assert_eq!(
                local.len(),
                1,
                "opener {opener:?} should hide local uses in its body"
            );
            assert_eq!(local[0].path, "./real");
        }
    }

    #[test]
    fn scan_tagged_flow_scalar_does_not_trigger_skip() {
        let yaml = "steps:\n  - run: !!str echo hello\n  - uses: actions/checkout@v4\n";
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "actions/checkout");
    }

    #[test]
    fn scan_bare_marker_without_yaml_context_does_not_trigger_skip() {
        let yaml = "steps:\n  |\n    - uses: actions/checkout@v4\n";
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].full_name(), "actions/checkout");
    }

    #[test]
    fn scan_skips_uses_inside_non_run_block_scalar() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          script: |
            const text = `
            - uses: bad/action@v1
            `;
      - uses: good/action@v2
"#;
        let refs = scan_content(yaml);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].full_name(), "actions/github-script");
        assert_eq!(refs[1].full_name(), "good/action");
    }

    #[test]
    fn scan_local_actions_skips_block_scalars() {
        let yaml = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          - uses: ./.github/actions/fake
      - uses: ./.github/actions/real
"#;
        let refs = scan_local_actions(yaml);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].path, "./.github/actions/real");
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

    // ── find_workflows ───────────────────────────────────────────────────

    #[test]
    fn find_workflows_returns_regular_yaml_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("b.yml"), "").unwrap();
        std::fs::write(workflows.join("a.yaml"), "").unwrap();
        std::fs::write(workflows.join("notes.txt"), "").unwrap();

        let files = find_workflows(dir.path()).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.path().file_name().unwrap().to_str().unwrap())
            .collect();

        assert_eq!(names, vec!["a.yaml", "b.yml"]);
    }

    #[cfg(unix)]
    #[test]
    fn find_workflows_rejects_symlinked_workflow_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let outside = dir.path().join("outside.yml");
        std::fs::write(&outside, "name: outside\n").unwrap();
        std::os::unix::fs::symlink(&outside, workflows.join("ci.yml")).unwrap();

        let err = find_workflows(dir.path()).unwrap_err();
        assert!(err.to_string().contains("symlinked workflow file"));
    }

    #[cfg(unix)]
    #[test]
    fn find_workflows_rejects_symlinked_workflows_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let github = dir.path().join(".github");
        let outside = dir.path().join("outside-workflows");
        std::fs::create_dir_all(&github).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, github.join("workflows")).unwrap();

        let err = find_workflows(dir.path()).unwrap_err();
        assert!(err.to_string().contains("symlinked directory"));
    }

    #[cfg(unix)]
    #[test]
    fn find_workflows_rejects_symlinked_github_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = dir.path().join("outside-github");
        std::fs::create_dir_all(outside.join("workflows")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join(".github")).unwrap();

        let err = find_workflows(dir.path()).unwrap_err();
        assert!(err.to_string().contains("symlinked directory"));
    }

    #[cfg(unix)]
    #[test]
    fn open_workflows_dirs_rejects_symlinked_workflows_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let github = dir.path().join(".github");
        let outside = dir.path().join("outside-workflows");
        std::fs::create_dir_all(&github).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, github.join("workflows")).unwrap();

        let err = open_workflows_dirs(dir.path(), DEFAULT_FORGE_ROOTS).unwrap_err();
        assert!(err.to_string().contains("symlinked directory"));
    }

    #[test]
    fn find_workflows_scans_forgejo_root() {
        // A Forgejo/Gitea repo with no `.github` at all is still scanned.
        let dir = tempfile::TempDir::new().unwrap();
        let workflows = dir.path().join(".forgejo").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("ci.yml"), "").unwrap();

        let files = find_workflows(dir.path()).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| display_path(p.path(), dir.path()))
            .collect();
        assert_eq!(names, vec![".forgejo/workflows/ci.yml"]);
    }

    #[test]
    fn find_workflows_unions_multiple_forge_roots() {
        // A repo mirrored across forges keeps workflows in several roots; every
        // existing root is scanned and the results merged (additive discovery).
        let dir = tempfile::TempDir::new().unwrap();
        for (root, name) in [(".github", "gh.yml"), (".gitea", "gitea.yml")] {
            let workflows = dir.path().join(root).join("workflows");
            std::fs::create_dir_all(&workflows).unwrap();
            std::fs::write(workflows.join(name), "").unwrap();
        }

        let files = find_workflows(dir.path()).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| display_path(p.path(), dir.path()))
            .collect();
        assert_eq!(
            names,
            vec![".gitea/workflows/gitea.yml", ".github/workflows/gh.yml"]
        );
    }

    #[test]
    fn find_workflows_skips_forge_root_without_workflows_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".github")).unwrap();
        let workflows = dir.path().join(".gitea/workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(workflows.join("ci.yml"), "").unwrap();

        let files = find_workflows(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            display_path(files[0].path(), dir.path()),
            ".gitea/workflows/ci.yml"
        );
    }

    #[test]
    fn find_workflows_error_lists_all_forge_roots() {
        // With no workflow directory anywhere, the error names every root tried
        // so the user knows a Forgejo/Gitea layout is also supported.
        let dir = tempfile::TempDir::new().unwrap();
        let err = find_workflows(dir.path()).unwrap_err().to_string();
        assert!(err.contains(".github/workflows/"));
        assert!(err.contains(".forgejo/workflows/"));
        assert!(err.contains(".gitea/workflows/"));
    }

    #[cfg(unix)]
    #[test]
    fn find_workflows_rejects_symlinked_forgejo_directory() {
        // The v0.18.0 symlink hardening applies to every forge root, not just
        // `.github`: a symlinked `.forgejo` is refused, never followed.
        let dir = tempfile::TempDir::new().unwrap();
        let outside = dir.path().join("outside-forgejo");
        std::fs::create_dir_all(outside.join("workflows")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join(".forgejo")).unwrap();

        let err = find_workflows(dir.path()).unwrap_err();
        assert!(err.to_string().contains("symlinked directory"));
    }

    #[cfg(unix)]
    #[test]
    fn read_workflow_rejects_file_swapped_to_symlink_after_discovery() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "ci.yml", "name: safe\n");
        let outside = dir.path().join("outside.yml");
        std::fs::write(&outside, "name: outside\n").unwrap();
        std::fs::remove_file(file.path()).unwrap();
        std::os::unix::fs::symlink(&outside, file.path()).unwrap();

        let err = read_workflow(&file).unwrap_err();
        assert!(is_unsafe_workflow_path(&err));
        assert!(err.to_string().contains("symlinked workflow file"));
    }

    #[test]
    fn read_workflow_reports_file_removed_after_discovery() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "ci.yml", "name: safe\n");
        std::fs::remove_file(file.path()).unwrap();

        let err = read_workflow(&file).unwrap_err();
        assert!(!is_unsafe_workflow_path(&err));
        assert!(err.to_string().contains("reading"));
    }

    #[test]
    fn child_path_helpers_reject_escaping_and_missing_paths() {
        let dir = tempfile::TempDir::new().unwrap();

        assert!(open_child_dir_path(dir.path(), Path::new("../outside")).is_err());
        assert!(open_child_file_path(dir.path(), Path::new("../outside")).is_err());
        assert!(
            open_child_dir_path(dir.path(), Path::new("missing/child"))
                .unwrap()
                .is_none()
        );
        assert!(
            open_child_file_path(dir.path(), Path::new("missing/child"))
                .unwrap()
                .is_none()
        );
        assert!(
            open_child_file_path(dir.path(), Path::new(""))
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn child_path_helpers_reject_non_utf8_and_symlinked_file() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::TempDir::new().unwrap();
        let invalid = PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]));
        assert!(open_child_dir_path(dir.path(), &invalid).is_err());
        assert!(open_child_file_path(dir.path(), &invalid).is_err());

        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked.yml")).unwrap();
        let err = open_child_file_path(dir.path(), Path::new("linked.yml")).unwrap_err();
        assert!(is_unsafe_workflow_path(&err));
        assert!(err.to_string().contains("symlinked file"));
    }

    // ── rewrite_actions ────────────────────────────────────────────────

    #[test]
    fn rewrite_preserves_trailing_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\nline2\n");
        let count =
            rewrite_actions(&file, &[(1, "line1".to_string(), "replaced".to_string())]).unwrap();
        assert_eq!(count, 1);
        let result = std::fs::read_to_string(file.path()).unwrap();
        assert!(result.ends_with('\n'));
        assert_eq!(result, "replaced\nline2\n");
    }

    #[test]
    fn rewrite_preserves_crlf() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\r\nline2\r\n");
        let count =
            rewrite_actions(&file, &[(1, "line1".to_string(), "replaced".to_string())]).unwrap();
        assert_eq!(count, 1);
        let result = std::fs::read_to_string(file.path()).unwrap();
        assert_eq!(result, "replaced\r\nline2\r\n");
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_preserves_unix_mode() {
        use std::os::unix::fs::PermissionsExt;

        for mode in [0o600, 0o750] {
            let dir = tempfile::TempDir::new().unwrap();
            let file = write_temp_workflow(&dir, "test.yml", "line1\nline2\n");
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();

            rewrite_actions(&file, &[(1, "line1".to_string(), "replaced".to_string())]).unwrap();

            let actual = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(actual, mode, "rewrite changed mode {mode:o} to {actual:o}");
        }
    }

    #[test]
    fn rewrite_no_trailing_newline() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\nline2");
        let count =
            rewrite_actions(&file, &[(1, "line1".to_string(), "replaced".to_string())]).unwrap();
        assert_eq!(count, 1);
        let result = std::fs::read_to_string(file.path()).unwrap();
        assert!(!result.ends_with('\n'));
    }

    #[test]
    fn rewrite_rejects_missing_line() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\n");
        let err =
            rewrite_actions(&file, &[(99, "old".to_string(), "nope".to_string())]).unwrap_err();
        assert!(err.to_string().contains("line 99 no longer exists"));
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "line1\n");
    }

    #[test]
    fn rewrite_rejects_zero_line_number() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\n");
        let err =
            rewrite_actions(&file, &[(0, "line1".to_string(), "nope".to_string())]).unwrap_err();
        assert!(err.to_string().contains("invalid line number 0"));
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "line1\n");
    }

    #[test]
    fn rewrite_does_not_clobber_line_changed_since_scan() {
        let dir = tempfile::TempDir::new().unwrap();
        let original = "name: ci\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n";
        let file = write_temp_workflow(&dir, "test.yml", original);
        let action = scan_workflow(&file).unwrap().remove(0);
        let replacement = build_pinned_line(
            &action.raw_line,
            "0123456789abcdef0123456789abcdef01234567",
            "v4.2.2",
        )
        .unwrap();

        let concurrent = original.replace(
            &action.raw_line,
            "      - run: echo 'concurrent edit must survive'",
        );
        std::fs::write(file.path(), &concurrent).unwrap();

        let err = rewrite_actions(&file, &[(action.line_number, action.raw_line, replacement)])
            .unwrap_err();
        assert!(err.to_string().contains("changed since it was scanned"));
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), concurrent);
    }

    #[test]
    fn rewrite_preserves_unrelated_changes_since_scan() {
        let dir = tempfile::TempDir::new().unwrap();
        let original = "name: ci\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n";
        let file = write_temp_workflow(&dir, "test.yml", original);
        let action = scan_workflow(&file).unwrap().remove(0);
        let replacement = build_pinned_line(
            &action.raw_line,
            "0123456789abcdef0123456789abcdef01234567",
            "v4.2.2",
        )
        .unwrap();

        let concurrent = original.replace("name: ci", "name: concurrently-renamed");
        std::fs::write(file.path(), concurrent).unwrap();

        let count = rewrite_actions(
            &file,
            &[(action.line_number, action.raw_line, replacement.clone())],
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            std::fs::read_to_string(file.path()).unwrap(),
            format!("name: concurrently-renamed\njobs:\n  test:\n    steps:\n{replacement}\n")
        );
    }

    #[test]
    fn rewrite_writes_nothing_when_any_target_changed() {
        let dir = tempfile::TempDir::new().unwrap();
        let original = "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/setup-node@v4\n";
        let file = write_temp_workflow(&dir, "test.yml", original);
        let actions = scan_workflow(&file).unwrap();
        let replacements: Vec<_> = actions
            .iter()
            .map(|action| {
                (
                    action.line_number,
                    action.raw_line.clone(),
                    build_pinned_line(
                        &action.raw_line,
                        "0123456789abcdef0123456789abcdef01234567",
                        "v4.2.2",
                    )
                    .unwrap(),
                )
            })
            .collect();

        let concurrent = original.replace(
            "  - uses: actions/setup-node@v4",
            "  - run: echo 'second target changed'",
        );
        std::fs::write(file.path(), &concurrent).unwrap();

        assert!(rewrite_actions(&file, &replacements).is_err());
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), concurrent);
    }

    #[test]
    fn rewrite_empty_replacements() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\n");
        let count = rewrite_actions(&file, &[]).unwrap();
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_does_not_follow_preexisting_temp_symlink() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "ci.yml", "      - uses: actions/checkout@v4\n");
        let victim = dir.path().join("victim.txt");
        let old_tmp = file.path().with_file_name(".ci.yml.pinprick-tmp");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, &old_tmp).unwrap();

        let replacement =
            "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v4"
                .to_string();
        let count = rewrite_actions(
            &file,
            &[(
                1,
                "      - uses: actions/checkout@v4".to_string(),
                replacement.clone(),
            )],
        )
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(
            std::fs::read_to_string(file.path()).unwrap(),
            format!("{replacement}\n")
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_rejects_file_swapped_to_symlink_before_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "ci.yml", "line1\n");
        let outside = dir.path().join("outside.yml");
        std::fs::write(&outside, "outside\n").unwrap();
        std::fs::remove_file(file.path()).unwrap();
        std::os::unix::fs::symlink(&outside, file.path()).unwrap();

        let err = rewrite_actions(&file, &[(1, "line1".to_string(), "replaced".to_string())])
            .unwrap_err();
        assert!(is_unsafe_workflow_path(&err));
        assert!(err.to_string().contains("symlinked workflow file"));
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside\n");
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn rewrite_duplicate_line_skipped_in_release() {
        // Release builds drop the duplicate instead of clobbering the earlier entry.
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\nline2\n");
        let count = rewrite_actions(
            &file,
            &[
                (1, "line1".to_string(), "first".to_string()),
                (
                    1,
                    "line1".to_string(),
                    "second-should-be-ignored".to_string(),
                ),
            ],
        )
        .unwrap();
        assert_eq!(count, 1);
        let result = std::fs::read_to_string(file.path()).unwrap();
        assert_eq!(result, "first\nline2\n");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "duplicate rewrite target")]
    fn rewrite_duplicate_line_panics_in_debug() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = write_temp_workflow(&dir, "test.yml", "line1\nline2\n");
        let _ = rewrite_actions(
            &file,
            &[
                (1, "line1".to_string(), "first".to_string()),
                (1, "line1".to_string(), "second".to_string()),
            ],
        );
    }
}
