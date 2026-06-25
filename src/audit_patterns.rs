use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub enum Category {
    DockerUnpinned,
    JavaScriptFetch,
    PythonFetch,
    ShellFetch,
}

pub struct Pattern {
    pub regex: &'static LazyLock<Regex>,
    pub severity: Severity,
    pub category: Category,
    pub description: &'static str,
}

// ── Shell patterns (for run: blocks and action.yml) ─────────────────────────

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        pub static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pattern).unwrap());
    };
}

re!(SH_CURL_LATEST, r#"curl\b.*[/=]latest(?:[/\s"]|$)"#);
re!(SH_WGET_LATEST, r#"wget\b.*[/=]latest(?:[/\s"]|$)"#);
// Matches every `gh release download`; gh_release_has_tag decides pinned vs latest.
re!(SH_GH_RELEASE_LATEST, r"gh\s+release\s+download\s");
re!(SH_CURL_UNVERSIONED, r#"curl\b.*https?://[^\s"']+"#);
re!(SH_WGET_UNVERSIONED, r#"wget\b.*https?://[^\s"']+"#);
// Install rules tolerate flags between `install` and the package —
// flag-first (`pip install -U requests`, `npm i -g yarn`) is the common idiom.
re!(
    SH_PIP_UNVERSIONED,
    r"pip3?\s+install\s+(?:-\S+\s+)*[a-zA-Z][a-zA-Z0-9_-]*(\s|$)"
);
re!(
    SH_NPM_UNVERSIONED,
    r"npm\s+(?:install|i)\s+(?:-\S+\s+)*(@[a-zA-Z][a-zA-Z0-9_-]*/)?[a-zA-Z][a-zA-Z0-9_-]*(\s|$)"
);
re!(
    SH_GO_INSTALL_LATEST,
    r"go\s+install\s+\S+@(?:latest|main|master)\b"
);
re!(
    SH_IWR_LATEST,
    r#"(?i)\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b.*[/=]latest(?:[/\s"]|$)"#
);
re!(
    SH_IWR_UNVERSIONED,
    r#"(?i)\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b.*https?://[^\s"']+"#
);

// The shell may sit any number of pipe stages after the fetch — `curl … | tr
// -d '\r' | bash` is as executable as a direct pipe.
re!(
    SH_PIPE_SHELL,
    r"(?i)\b(curl|wget)\b[^|]*(?:\|[^|]*)*\|\s*(?:(?:sudo|env|command|xargs)\s+)*(?:\S*/)?(bash|sh|zsh|dash|ash|ksh|fish|python3?|node(?:js)?|ruby|perl|pwsh|powershell)\b"
);
re!(
    SH_PROC_SUB_FETCH,
    r"(?i)\b(bash|sh|zsh|dash|ash|ksh|fish|python3?|source)\s+<\(\s*(curl|wget)\b"
);
// Requires an execution context — `bash … -c "$( … )"` or `eval "$( … )"`.
// A bare `script.sh "$(curl …)"` passes fetched bytes as an argument, which
// does not execute them, and `sh` matching inside the script's filename made
// that a high-severity false positive.
re!(
    SH_CMD_SUB_FETCH,
    r#"(?i)\b(?:(?:bash|sh|zsh|dash|ash|ksh|fish)\b[^|&;]*?\s-\w*c\s+|eval\b[^|&;]*?)["']?\$\(\s*(curl|wget)\b"#
);
re!(
    SH_IEX_FETCH,
    r"(?i)\b(iex|Invoke-Expression)\b.*\b(iwr|Invoke-WebRequest|Invoke-RestMethod|irm|DownloadString)\b"
);

re!(SH_GIT_CLONE, r"git\s+clone\s");
re!(GIT_CHECKOUT_SHA, r"git\s+checkout\s+[0-9a-f]{40}\b");
re!(
    SH_CARGO_INSTALL_UNVERSIONED,
    r"cargo\s+install\s+(?:-\S+\s+)*[a-zA-Z][a-zA-Z0-9_-]*(\s|$)"
);
re!(
    SH_GEM_INSTALL_UNVERSIONED,
    r"gem\s+install\s+(?:-\S+\s+)*[a-zA-Z][a-zA-Z0-9_-]*(\s|$)"
);
re!(
    SH_NPX_UNVERSIONED,
    r"\bnpx\s+(-\S+\s+)*(@[a-zA-Z][a-zA-Z0-9_-]*/)?[a-zA-Z][a-zA-Z0-9_-]*"
);
re!(SH_BREW_HEAD, r"(?i)\bbrew\s+install\b[^\n]*--head\b");
re!(
    PS_INSTALL_MODULE_UNVERSIONED,
    r"(?i)\bInstall-(Module|Script)\b"
);
re!(
    SH_PIP_GIT_URL_UNVERSIONED,
    r"pip3?\s+install\b[^#\n]*\bgit\+https?://\S+"
);

pub static SHELL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &SH_CURL_LATEST,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "curl fetching from a 'latest' URL — can change without notice",
        },
        Pattern {
            regex: &SH_WGET_LATEST,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "wget fetching from a 'latest' URL — can change without notice",
        },
        Pattern {
            regex: &SH_GO_INSTALL_LATEST,
            severity: Severity::Medium,
            category: Category::ShellFetch,
            description: "go install @latest/@main — not version-pinned",
        },
        Pattern {
            regex: &SH_IWR_LATEST,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "PowerShell fetching from a 'latest' URL — can change without notice",
        },
        Pattern {
            regex: &SH_BREW_HEAD,
            severity: Severity::Medium,
            category: Category::ShellFetch,
            description: "brew install --HEAD — builds from upstream main, bypasses pinning",
        },
    ]
});

// Patterns that are only flagged if the URL is unversioned
pub static SHELL_URL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &SH_CURL_UNVERSIONED,
            severity: Severity::Medium,
            category: Category::ShellFetch,
            description: "curl fetching URL without version pinning",
        },
        Pattern {
            regex: &SH_WGET_UNVERSIONED,
            severity: Severity::Medium,
            category: Category::ShellFetch,
            description: "wget fetching URL without version pinning",
        },
        Pattern {
            regex: &SH_IWR_UNVERSIONED,
            severity: Severity::Medium,
            category: Category::ShellFetch,
            description: "PowerShell fetching URL without version pinning",
        },
    ]
});

// Scanned before (and pre-empt) the regular shell patterns so `curl ... | sh`
// produces a single high-severity finding. Not subject to checksum suppression —
// a piped payload is never written to disk and cannot be verified.
pub static SHELL_PIPE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &SH_PIPE_SHELL,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "fetch piped to shell — payload not written to disk, cannot be checksummed",
        },
        Pattern {
            regex: &SH_PROC_SUB_FETCH,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "shell reading fetched content via process substitution — bypasses pinning",
        },
        Pattern {
            regex: &SH_CMD_SUB_FETCH,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "shell executing fetched content via command substitution — bypasses pinning",
        },
        Pattern {
            regex: &SH_IEX_FETCH,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "PowerShell Invoke-Expression on fetched content — bypasses pinning",
        },
    ]
});

// ── JavaScript patterns ─────────────────────────────────────────────────────

re!(JS_FETCH_LATEST, r#"fetch\s*\(.*[/=]latest[/\s"']"#);
re!(JS_AXIOS_LATEST, r#"axios\.\w+\s*\(.*[/=]latest[/\s"']"#);
re!(JS_GOT_LATEST, r#"got\s*\(.*[/=]latest[/\s"']"#);
re!(JS_HTTP_LATEST, r#"https?\.get\s*\(.*[/=]latest[/\s"']"#);
re!(
    JS_EXEC_SPAWN_CURL,
    r"\b(?:exec|spawn)\w*\s*\(.*\b(curl|wget)\b"
);
re!(JS_CHILD_PROC_CURL, r"child_process.*\bcurl\b");
re!(JS_FETCH_URL, r#"fetch\s*\(\s*["'`]https?://"#);
re!(JS_AXIOS_URL, r#"axios\.\w+\s*\(\s*["'`]https?://"#);
re!(JS_GOT_URL, r#"\bgot(?:\.\w+)?\s*\(\s*["'`]https?://"#);
re!(JS_HTTP_URL, r#"https?\.get\s*\(\s*["'`]https?://"#);
re!(
    JS_REQUIRE_HTTP_GET,
    r#"require\(\s*["'](?:node:)?https?["']\s*\)\.get\s*\(\s*["'`]https?://"#
);

pub static JS_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &JS_FETCH_LATEST,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "fetch() with 'latest' URL — runtime supply chain risk",
        },
        Pattern {
            regex: &JS_AXIOS_LATEST,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "axios request to 'latest' URL",
        },
        Pattern {
            regex: &JS_GOT_LATEST,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "got() request to 'latest' URL",
        },
        Pattern {
            regex: &JS_HTTP_LATEST,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "http.get() to 'latest' URL",
        },
        Pattern {
            regex: &JS_EXEC_SPAWN_CURL,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "exec()/spawn() shelling out to curl/wget — runtime fetch bypasses pinning",
        },
        Pattern {
            regex: &JS_CHILD_PROC_CURL,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "child_process curl — runtime fetch bypasses pinning",
        },
    ]
});

pub static JS_URL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &JS_FETCH_URL,
            severity: Severity::Medium,
            category: Category::JavaScriptFetch,
            description: "fetch() to external URL without version pinning",
        },
        Pattern {
            regex: &JS_AXIOS_URL,
            severity: Severity::Medium,
            category: Category::JavaScriptFetch,
            description: "axios request to external URL without version pinning",
        },
        Pattern {
            regex: &JS_GOT_URL,
            severity: Severity::Medium,
            category: Category::JavaScriptFetch,
            description: "got() request to external URL without version pinning",
        },
        Pattern {
            regex: &JS_HTTP_URL,
            severity: Severity::Medium,
            category: Category::JavaScriptFetch,
            description: "http.get() to external URL without version pinning",
        },
        Pattern {
            regex: &JS_REQUIRE_HTTP_GET,
            severity: Severity::Medium,
            category: Category::JavaScriptFetch,
            description: "http.get() to external URL without version pinning",
        },
    ]
});

// ── Docker patterns ─────────────────────────────────────────────────────────

// `FROM` may carry flags (`--platform=…`) before the image reference.
re!(DOCKER_FROM_LATEST, r"(?i)^FROM\s+(?:--\S+\s+)*\S+:latest\b");
// The image char class omits `:` and `@`, so tagged or digest-pinned
// references fail the trailing boundary and don't match.
re!(
    DOCKER_FROM_UNTAGGED,
    r"(?i)^FROM\s+(?:--\S+\s+)*[a-z][a-z0-9._/-]*(\s|$)"
);
re!(DOCKER_FROM_DIGEST, r"(?i)^FROM\s+(?:--\S+\s+)*\S+@sha256:");
re!(DOCKER_RUN_CURL, r"(?i)^RUN\b.*\bcurl\b");
re!(DOCKER_RUN_WGET, r"(?i)^RUN\b.*\bwget\b");
re!(DOCKER_ADD_URL, r"(?i)^ADD\b[^#]*\bhttps?://\S+");

pub static DOCKER_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &DOCKER_FROM_LATEST,
            severity: Severity::High,
            category: Category::DockerUnpinned,
            description: "FROM :latest — image not pinned to specific version",
        },
        Pattern {
            regex: &DOCKER_FROM_UNTAGGED,
            severity: Severity::High,
            category: Category::DockerUnpinned,
            description: "FROM without tag — implicitly pulls :latest",
        },
        Pattern {
            regex: &DOCKER_RUN_CURL,
            severity: Severity::Medium,
            category: Category::DockerUnpinned,
            description: "curl in Dockerfile RUN — check URL is versioned",
        },
        Pattern {
            regex: &DOCKER_RUN_WGET,
            severity: Severity::Medium,
            category: Category::DockerUnpinned,
            description: "wget in Dockerfile RUN — check URL is versioned",
        },
    ]
});

pub static DOCKER_URL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![Pattern {
        regex: &DOCKER_ADD_URL,
        severity: Severity::Medium,
        category: Category::DockerUnpinned,
        description: "Dockerfile ADD with URL source — build-time fetch bypasses pinning",
    }]
});

// ── Python patterns ─────────────────────────────────────────────────────────

re!(
    PY_URLLIB_LATEST,
    r#"urllib\.request\.urlopen\s*\(.*[/=]latest[/\s"']"#
);
re!(
    PY_REQUESTS_LATEST,
    r#"requests\.(get|post|head)\s*\(.*[/=]latest[/\s"']"#
);
re!(PY_SUBPROCESS_CURL, r"subprocess\b.*\bcurl\b");
re!(PY_SUBPROCESS_WGET, r"subprocess\b.*\bwget\b");
re!(
    PY_URLLIB_URL,
    r#"urllib\.request\.urlopen\s*\(\s*["']https?://"#
);
re!(
    PY_REQUESTS_URL,
    r#"requests\.(get|post|head)\s*\(\s*["']https?://"#
);

pub static PY_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &PY_URLLIB_LATEST,
            severity: Severity::High,
            category: Category::PythonFetch,
            description: "urllib fetching from a 'latest' URL",
        },
        Pattern {
            regex: &PY_REQUESTS_LATEST,
            severity: Severity::High,
            category: Category::PythonFetch,
            description: "requests library fetching from a 'latest' URL",
        },
        Pattern {
            regex: &PY_SUBPROCESS_CURL,
            severity: Severity::High,
            category: Category::PythonFetch,
            description: "subprocess shelling out to curl — runtime fetch bypasses pinning",
        },
        Pattern {
            regex: &PY_SUBPROCESS_WGET,
            severity: Severity::High,
            category: Category::PythonFetch,
            description: "subprocess shelling out to wget — runtime fetch bypasses pinning",
        },
    ]
});

pub static PY_URL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        Pattern {
            regex: &PY_URLLIB_URL,
            severity: Severity::Medium,
            category: Category::PythonFetch,
            description: "urllib fetching external URL without version pinning",
        },
        Pattern {
            regex: &PY_REQUESTS_URL,
            severity: Severity::Medium,
            category: Category::PythonFetch,
            description: "requests library fetching external URL without version pinning",
        },
    ]
});

// ── Checksum verification ───────────────────────────────────────────────────

re!(
    CHECKSUM_VERIFY,
    r"(?i)(sha256sum|sha512sum|shasum|openssl\s+dgst|gpg\b[^\n]*--verify|cosign\s+verify|minisign\s+-V|Get-FileHash)"
);

pub fn has_checksum_verify(line: &str) -> bool {
    CHECKSUM_VERIFY.is_match(line)
}

// ── Fetch-to-jq detection ───────────────────────────────────────────────────

// A pipe into `jq`. The trailing `\b` keeps `jqfoo` (and a path-qualified
// `| /usr/bin/jq`, deliberately) from matching — erring toward flagging.
re!(SH_PIPE_JQ, r"\|\s*jq\b");

/// Whether a line pipes a fetch into `jq`. `jq` parses JSON and errors on
/// anything else, so the fetched bytes are data, not executable code — the same
/// rationale as the data-format-extension exemption, but for an API endpoint
/// that carries no file extension (e.g. `https://crates.io/api/v1/crates/<x>`).
/// Pipe-to-shell matches and pre-empts the URL rules, so a
/// `curl … | jq … | bash` line never reaches this check.
pub fn fetch_piped_to_jq(line: &str) -> bool {
    SH_PIPE_JQ.is_match(line)
}

// ── URL version detection ───────────────────────────────────────────────────

// Requires at least one dotted component (e.g. `v1.2`, `1.2.3`) so that a
// bare `/v1/` or `/v2/` in a REST URL does not register as a pinned version.
// That is intentional — a single-digit major is a sliding namespace, not a
// release. Callers who want to exempt such hosts should use the
// `trusted-hosts` config instead of relaxing this regex.
// Leading `-`/`_` admit versions embedded in filenames (`tool-1.2.3.tar.gz`);
// the trailing class admits a following extension dot, suffix (`-rc1`), or end
// of string (a URL whose path ends at the version, e.g. `/download/v1.2.3`).
static VERSION_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[-_/]v?\d+(\.\d+)+(?:[-_./\s"]|$)"#).unwrap());

/// Check if a URL contains a version segment in its **path** — not its host or
/// query string. Scanning the authority or query too would let a
/// versioned-looking host or inert parameter whitelist an otherwise unpinned
/// fetch, which is a detection bypass.
pub fn url_has_version(s: &str) -> bool {
    VERSION_SEGMENT.is_match(url_path(s))
}

/// Return the path of an `http(s)://` URL (everything from the first `/` after
/// the authority until `?` or `#`). Returns `""` for a URL with no path, and
/// the input unchanged for a string that is not an `http(s)://` URL.
fn url_path(url: &str) -> &str {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return url;
    };
    // The path starts at the first `/`, which also ends the authority. Any
    // `user@host` userinfo and any `@` in a later path segment or query are
    // therefore excluded without special-casing `@`.
    match rest.find('/') {
        Some(i) => rest[i..].split(['?', '#']).next().unwrap_or_default(),
        None => "",
    }
}

/// File extensions whose contents are parsed as data rather than executed.
/// Fetches to these are downgraded to allowed matches.
const DATA_FORMAT_EXTENSIONS: &[&str] = &[
    "json", "jsonl", "ndjson", "yaml", "yml", "toml", "xml", "csv", "tsv", "txt", "md", "rst",
];

/// Extract the filename extension from a URL's path. Query strings and
/// fragments are stripped. Returns `None` if the final path segment has no dot.
pub fn url_extension(url: &str) -> Option<&str> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let last = path.rsplit('/').next().unwrap_or("");
    let dot = last.rfind('.')?;
    Some(&last[dot + 1..])
}

/// Extract the hostname from an `http(s)://` URL. Strips the protocol,
/// optional `user@` prefix, and trailing port/path/query/fragment. Returns
/// `None` if the URL does not start with `http://` or `https://`.
pub fn url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let after_userinfo = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
    let end = after_userinfo
        .find(['/', ':', '?', '#'])
        .unwrap_or(after_userinfo.len());
    Some(&after_userinfo[..end])
}

/// Check if a URL's path ends with a known data-format extension.
pub fn url_is_data_format(url: &str) -> bool {
    let Some(ext) = url_extension(url) else {
        return false;
    };
    DATA_FORMAT_EXTENSIONS
        .iter()
        .any(|e| ext.eq_ignore_ascii_case(e))
}

// URLs end at whitespace, quotes, backticks, `)`, or `>` so string-literal and
// markdown-link syntax never rides into the version/extension/host checks.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s"'`)>]+"#).unwrap());

/// Extract every URL from a line, in order of appearance.
pub fn extract_urls(line: &str) -> impl Iterator<Item = &str> {
    URL_RE.find_iter(line).map(|m| m.as_str())
}

/// Check if a `gh release download` line has a version tag argument.
/// `gh release download v1.2.3 --pattern ...` is pinned (positional).
/// `gh release download -R owner/repo v1.2.3 ...` is pinned (flags may
/// precede the tag). `gh release download --pattern ...` grabs latest.
pub fn gh_release_has_tag(line: &str) -> bool {
    static GH_RELEASE_ARGS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"gh\s+release\s+download\s+(.+)").unwrap());
    let Some(caps) = GH_RELEASE_ARGS.captures(line) else {
        return false;
    };
    // `gh release download` flags that consume a value; the tag itself is
    // positional only, so skip flags (and their values) to find it.
    const VALUE_FLAGS: &[&str] = &[
        "-R",
        "--repo",
        "-p",
        "--pattern",
        "-D",
        "--dir",
        "-O",
        "--output",
        "-A",
        "--archive",
    ];
    let mut tokens = caps[1].split_whitespace();
    while let Some(tok) = tokens.next() {
        // `--tag` isn't a real gh flag, but honor its value as the tag for
        // lines written against tools that accept it.
        if tok == "--tag" {
            return tokens.next().is_some_and(looks_like_version_token);
        }
        if VALUE_FLAGS.contains(&tok) {
            tokens.next(); // skip the flag's value
        } else if !tok.starts_with('-') {
            // First positional argument is the release tag.
            return looks_like_version_token(tok);
        }
    }
    false
}

/// `v1.2.3`, `1.2.3`, `v2` — a token that starts like a version tag.
fn looks_like_version_token(tok: &str) -> bool {
    let digits = tok.strip_prefix('v').unwrap_or(tok);
    digits.starts_with(|c: char| c.is_ascii_digit())
}

/// Check if a ref argument looks like a version tag rather than a branch name.
/// Returns true for: v1.2.3, 1.2.3, release/1.0.0 (contains version segment).
/// Returns false for: main, master, develop, feature/foo.
fn ref_looks_versioned(ref_name: &str) -> bool {
    static VERSION_REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"v?\d+(\.\d+)+").unwrap());
    VERSION_REF.is_match(ref_name)
}

/// Check if a `git clone` line has a pinned ref via `--branch`/`-b`.
///
/// `git clone --branch v1.2.3 ...` is pinned.
/// `git clone -b main ...` is not.
/// `git clone ...` (no branch flag) is not.
pub fn git_clone_has_pinned_ref(line: &str) -> bool {
    static GIT_CLONE_BRANCH: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"git\s+clone\s+.*(?:--branch|-b)\s+(\S+)").unwrap());
    let Some(caps) = GIT_CLONE_BRANCH.captures(line) else {
        return false;
    };
    ref_looks_versioned(&caps[1])
}

/// Check if a line contains a `git checkout <full-SHA>`.
pub fn has_git_checkout_sha(line: &str) -> bool {
    GIT_CHECKOUT_SHA.is_match(line)
}

/// The stage name a `FROM … AS <name>` line declares, lowercased. Tolerates a
/// leading `--platform=…` flag by matching the trailing `AS <name>` rather than
/// a fixed position. Returns `None` when the line declares no stage alias.
pub fn dockerfile_stage_alias(line: &str) -> Option<String> {
    static FROM_AS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)^FROM\b.*\bAS\s+(\S+)\s*$").unwrap());
    FROM_AS.captures(line).map(|c| c[1].to_ascii_lowercase())
}

/// The base image/stage a `FROM <base>` line references, lowercased. Returns
/// `None` when the line is not a `FROM` instruction.
pub fn dockerfile_from_base(line: &str) -> Option<String> {
    static FROM_BASE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)^FROM\s+(?:--\S+\s+)*(\S+)").unwrap());
    FROM_BASE.captures(line).map(|c| c[1].to_ascii_lowercase())
}

/// Check if a `pip install` line has a version specifier or uses `-r`.
pub fn pip_install_has_version(line: &str) -> bool {
    static PIP_VERSION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"pip3?\s+install\s+(?:-\S+\s+)*\S*[=>~]=|pip3?\s+install\b.*\s(-r|--requirement)\s",
        )
        .unwrap()
    });
    PIP_VERSION.is_match(line)
}

/// Check if an `npm install` line has a version pin (`@version` after the package name).
/// Scoped packages (`@babel/core`) are not version-pinned; `@babel/core@1.0.0` is.
pub fn npm_install_has_version(line: &str) -> bool {
    static NPM_VERSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"npm\s+(?:install|i)\s+(?:-\S+\s+)*\S+@\d").unwrap());
    NPM_VERSION.is_match(line)
}

/// Check if a `cargo install` line has a version pin (`@version` or `--version`).
pub fn cargo_install_has_version(line: &str) -> bool {
    static CARGO_VERSION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"cargo\s+install\s+(?:-\S+\s+)*\S+@\d|cargo\s+install\s+.*--version\s").unwrap()
    });
    CARGO_VERSION.is_match(line)
}

/// Check if a `gem install` line has a version pin (`-v` or `--version`).
pub fn gem_install_has_version(line: &str) -> bool {
    static GEM_VERSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"gem\s+install\s+.*(-v\s+\d|--version\s)").unwrap());
    GEM_VERSION.is_match(line)
}

/// Check if an `npx` line has a version pin on any token (`@<version>`).
pub fn npx_has_version(line: &str) -> bool {
    static NPX_VERSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\bnpx\s+.*\S+@\d").unwrap());
    NPX_VERSION.is_match(line)
}

/// Check if a PowerShell `Install-Module`/`Install-Script` line has `-RequiredVersion`.
pub fn ps_install_has_required_version(line: &str) -> bool {
    static PS_VERSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)-RequiredVersion\s+\S+").unwrap());
    PS_VERSION.is_match(line)
}

/// Whether a `pip install git+https://…` line is pinned to an immutable ref: a
/// full 40-char SHA or a version-like tag (`@v1.2.3`). A branch ref (`@main`) is
/// not — it tracks HEAD, the risk this rule flags. The greedy `\S+` anchors on
/// the last `@`, so a `user@host` prefix isn't mistaken for the ref.
pub fn pip_git_url_has_ref(line: &str) -> bool {
    static GIT_URL_REF: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\bgit\+https?://\S+@([^@#\s]+)").unwrap());
    let Some(caps) = GIT_URL_REF.captures(line) else {
        return false;
    };
    let git_ref = &caps[1];
    is_full_sha(git_ref) || ref_looks_versioned(git_ref)
}

/// True if `s` is a full 40-character hex commit SHA.
fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn category_str(c: &Category) -> &'static str {
    match c {
        Category::DockerUnpinned => "docker_unpinned",
        Category::JavaScriptFetch => "javascript_fetch",
        Category::PythonFetch => "python_fetch",
        Category::ShellFetch => "shell_fetch",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── url_has_version ─────────────────────────────────────────────────

    #[test]
    fn versioned_download_url() {
        assert!(url_has_version(
            "https://github.com/nicklockwood/SwiftFormat/releases/download/0.55.8/swiftformat"
        ));
    }

    #[test]
    fn versioned_with_v_prefix() {
        assert!(url_has_version(
            "https://example.com/releases/download/v2.8.1/tool.tar.xz"
        ));
    }

    #[test]
    fn unversioned_latest_url() {
        assert!(!url_has_version(
            "https://github.com/aquasecurity/trivy/releases/latest/download/trivy.tar.gz"
        ));
    }

    #[test]
    fn unversioned_api_url() {
        assert!(!url_has_version("https://api.example.com/data"));
    }

    #[test]
    fn single_number_not_version() {
        // A single number segment like /v4/ is not multi-component, so not matched
        assert!(!url_has_version("https://example.com/v4/resource"));
    }

    #[test]
    fn versioned_final_path_segment() {
        // Version as the last path segment — nothing follows it.
        assert!(url_has_version("https://example.com/download/v1.2.3"));
    }

    #[test]
    fn versioned_in_filename() {
        assert!(url_has_version("https://example.com/dl/tool-1.2.3.tar.gz"));
        assert!(url_has_version("https://example.com/openssl_3.0.13.tar.gz"));
    }

    #[test]
    fn query_only_version_is_not_versioned() {
        assert!(!url_has_version(
            "https://example.com/download/install.sh?version=1.2.3"
        ));
        assert!(!url_has_version(
            "https://example.com/download/install.sh?v=1.2.3#release"
        ));
        assert!(url_has_version(
            "https://example.com/releases/v1.2.3/install.sh?cache=false"
        ));
    }

    #[test]
    fn at_sign_past_authority_does_not_break_path_version() {
        // A `@` in a later path segment or query must not truncate the path:
        // the version is still found and the URL counts as pinned.
        assert!(url_has_version(
            "https://example.com/releases/v1.2.3/tool?token=a@b"
        ));
        assert!(url_has_version(
            "https://user@example.com/releases/v1.2.3/tool"
        ));
    }

    #[test]
    fn arch_suffix_not_version() {
        // `x86_64` must not read as a version — no dotted component.
        assert!(!url_has_version("https://example.com/setup-x86_64.sh"));
        assert!(!url_has_version("https://example.com/tool-linux-amd64.sh"));
    }

    #[test]
    fn versioned_looking_host_not_counted() {
        // A bare-IP host (or a version-shaped authority) must NOT register as a
        // pinned version — only the path is scanned, so these still fire.
        assert!(!url_has_version("https://10.0.0.1/install.sh"));
        assert!(!url_has_version("https://1.2.3.4/get.sh"));
        // …but a real version in the path still counts.
        assert!(url_has_version("https://10.0.0.1/v1.2.3/install.sh"));
    }

    // ── url_extension ───────────────────────────────────────────────────

    #[test]
    fn url_extension_simple() {
        assert_eq!(url_extension("https://example.com/data.json"), Some("json"));
    }

    #[test]
    fn url_extension_strips_query_string() {
        assert_eq!(
            url_extension("https://example.com/data.json?cache=false"),
            Some("json")
        );
    }

    #[test]
    fn url_extension_strips_fragment() {
        assert_eq!(
            url_extension("https://example.com/doc.md#section"),
            Some("md")
        );
    }

    #[test]
    fn url_extension_no_extension() {
        assert_eq!(url_extension("https://api.github.com/user"), None);
    }

    #[test]
    fn url_extension_dot_only_in_earlier_segment() {
        assert_eq!(
            url_extension("https://example.com/v1.2.3/config/settings"),
            None
        );
    }

    // ── url_host ────────────────────────────────────────────────────────

    #[test]
    fn url_host_simple_https() {
        assert_eq!(
            url_host("https://example.com/path/to/file"),
            Some("example.com")
        );
    }

    #[test]
    fn url_host_simple_http() {
        assert_eq!(url_host("http://example.com/"), Some("example.com"));
    }

    #[test]
    fn url_host_with_port_strips_port() {
        assert_eq!(
            url_host("https://example.com:8080/api"),
            Some("example.com")
        );
    }

    #[test]
    fn url_host_with_query() {
        assert_eq!(url_host("https://example.com?foo=bar"), Some("example.com"));
    }

    #[test]
    fn url_host_with_fragment() {
        assert_eq!(url_host("https://example.com#section"), Some("example.com"));
    }

    #[test]
    fn url_host_bare() {
        assert_eq!(url_host("https://example.com"), Some("example.com"));
    }

    #[test]
    fn url_host_strips_userinfo() {
        assert_eq!(
            url_host("https://user@example.com/path"),
            Some("example.com")
        );
    }

    #[test]
    fn url_host_subdomain() {
        assert_eq!(
            url_host("https://api.example.com/data"),
            Some("api.example.com")
        );
    }

    #[test]
    fn url_host_not_a_url() {
        assert_eq!(url_host("example.com"), None);
        assert_eq!(url_host("ftp://example.com"), None);
    }

    // ── url_is_data_format ──────────────────────────────────────────────

    #[test]
    fn data_format_json() {
        assert!(url_is_data_format(
            "https://formulae.brew.sh/api/analytics/install/homebrew-core/30d.json"
        ));
    }

    #[test]
    fn data_format_yaml() {
        assert!(url_is_data_format("https://example.com/config.yaml"));
        assert!(url_is_data_format("https://example.com/config.yml"));
    }

    #[test]
    fn data_format_toml() {
        assert!(url_is_data_format("https://example.com/settings.toml"));
    }

    #[test]
    fn data_format_csv_tsv_xml() {
        assert!(url_is_data_format("https://example.com/data.csv"));
        assert!(url_is_data_format("https://example.com/data.tsv"));
        assert!(url_is_data_format("https://example.com/data.xml"));
    }

    #[test]
    fn data_format_markdown() {
        assert!(url_is_data_format(
            "https://raw.githubusercontent.com/owner/repo/main/README.md"
        ));
    }

    #[test]
    fn data_format_case_insensitive() {
        assert!(url_is_data_format("https://example.com/DATA.JSON"));
    }

    #[test]
    fn data_format_with_query_string() {
        assert!(url_is_data_format(
            "https://example.com/data.json?cache=false"
        ));
    }

    #[test]
    fn data_format_with_fragment() {
        assert!(url_is_data_format("https://example.com/doc.md#section"));
    }

    #[test]
    fn data_format_jsonl_ndjson() {
        assert!(url_is_data_format("https://example.com/events.jsonl"));
        assert!(url_is_data_format("https://example.com/events.ndjson"));
    }

    #[test]
    fn not_data_format_shell_script() {
        assert!(!url_is_data_format("https://example.com/install.sh"));
    }

    #[test]
    fn not_data_format_archive() {
        assert!(!url_is_data_format("https://example.com/tool.tar.gz"));
        assert!(!url_is_data_format("https://example.com/bundle.zip"));
    }

    #[test]
    fn not_data_format_executable() {
        assert!(!url_is_data_format("https://example.com/tool.exe"));
        assert!(!url_is_data_format("https://example.com/tool"));
    }

    #[test]
    fn not_data_format_html() {
        assert!(!url_is_data_format("https://example.com/page.html"));
    }

    #[test]
    fn not_data_format_no_extension() {
        assert!(!url_is_data_format("https://api.github.com/user"));
    }

    #[test]
    fn not_data_format_path_ends_with_dot_in_earlier_segment() {
        assert!(!url_is_data_format(
            "https://example.com/v1.2.3/config/settings"
        ));
    }

    // ── extract_urls ────────────────────────────────────────────────────

    #[test]
    fn extract_url_from_curl() {
        let line = r#"curl -L "https://example.com/file.tar.gz" -o out"#;
        assert_eq!(
            extract_urls(line).next(),
            Some("https://example.com/file.tar.gz")
        );
    }

    #[test]
    fn extract_url_single_quotes() {
        let line = "wget 'https://example.com/file'";
        assert_eq!(extract_urls(line).next(), Some("https://example.com/file"));
    }

    #[test]
    fn no_url() {
        assert!(extract_urls("echo hello world").next().is_none());
    }

    #[test]
    fn extract_urls_returns_all_urls_in_order() {
        let line = "curl https://a.example/v1.2.3/x https://b.example/y -o out";
        let urls: Vec<&str> = extract_urls(line).collect();
        assert_eq!(
            urls,
            vec!["https://a.example/v1.2.3/x", "https://b.example/y"]
        );
    }

    // ── Shell patterns ──────────────────────────────────────────────────

    #[test]
    fn curl_latest_detected() {
        assert!(
            SH_CURL_LATEST.is_match(
                r#"curl -L "https://github.com/owner/repo/releases/latest/download/tool""#
            )
        );
    }

    #[test]
    fn curl_versioned_not_flagged_as_latest() {
        assert!(
            !SH_CURL_LATEST.is_match(
                r#"curl -L "https://github.com/owner/repo/releases/download/v1.2.3/tool""#
            )
        );
    }

    #[test]
    fn wget_latest_detected() {
        assert!(
            SH_WGET_LATEST.is_match(r#"wget "https://example.com/releases/latest/tool.tar.gz""#)
        );
    }

    #[test]
    fn gh_release_download_unversioned() {
        assert!(SH_GH_RELEASE_LATEST.is_match("gh release download --pattern '*.tar.gz'"));
        assert!(!gh_release_has_tag(
            "gh release download --pattern '*.tar.gz'"
        ));
    }

    #[test]
    fn gh_release_download_versioned() {
        assert!(SH_GH_RELEASE_LATEST.is_match("gh release download v1.2.3 --pattern '*.tar.gz'"));
        assert!(gh_release_has_tag(
            "gh release download v1.2.3 --pattern '*.tar.gz'"
        ));
    }

    #[test]
    fn gh_release_download_versioned_tag_flag() {
        assert!(
            SH_GH_RELEASE_LATEST.is_match("gh release download --tag v1.2.3 --pattern '*.tar.gz'")
        );
        assert!(gh_release_has_tag(
            "gh release download --tag v1.2.3 --pattern '*.tar.gz'"
        ));
    }

    #[test]
    fn gh_release_download_flag_first_versioned() {
        // Flags (with values) may precede the positional tag.
        assert!(gh_release_has_tag(
            "gh release download -R owner/repo v1.2.3 -p '*.tar.gz'"
        ));
        assert!(gh_release_has_tag(
            "gh release download --repo owner/repo --pattern '*.tar.gz' v1.2.3"
        ));
    }

    #[test]
    fn gh_release_download_flag_first_unversioned() {
        // A flag's value must not be mistaken for the tag.
        assert!(!gh_release_has_tag(
            "gh release download -R owner/repo -p '*.tar.gz'"
        ));
        assert!(!gh_release_has_tag(
            "gh release download --clobber -D out -p '*.tar.gz'"
        ));
    }

    #[test]
    fn go_install_latest_detected() {
        assert!(
            SH_GO_INSTALL_LATEST
                .is_match("go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest")
        );
    }

    #[test]
    fn go_install_versioned_not_flagged() {
        assert!(
            !SH_GO_INSTALL_LATEST
                .is_match("go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0")
        );
    }

    #[test]
    fn go_install_branch_ref_detected() {
        // @main/@master track HEAD exactly like @latest.
        assert!(SH_GO_INSTALL_LATEST.is_match("go install example.com/tool@main"));
        assert!(SH_GO_INSTALL_LATEST.is_match("go install example.com/tool@master"));
    }

    #[test]
    fn npm_install_unversioned_detected() {
        assert!(SH_NPM_UNVERSIONED.is_match("npm install typescript"));
        assert!(SH_NPM_UNVERSIONED.is_match("npm install svelte-kit"));
    }

    #[test]
    fn npm_install_scoped_unversioned_detected() {
        assert!(SH_NPM_UNVERSIONED.is_match("npm install @babel/core"));
    }

    #[test]
    fn npm_install_version_pinned_not_flagged() {
        assert!(!SH_NPM_UNVERSIONED.is_match("npm install typescript@5.6.0"));
        assert!(!SH_NPM_UNVERSIONED.is_match("npm install @babel/core@1.0.0"));
    }

    #[test]
    fn npm_install_no_args_not_flagged() {
        assert!(!SH_NPM_UNVERSIONED.is_match("npm install"));
    }

    #[test]
    fn npm_install_flag_first_detected() {
        assert!(SH_NPM_UNVERSIONED.is_match("npm install -g yarn"));
        assert!(SH_NPM_UNVERSIONED.is_match("npm i -g yarn"));
        assert!(SH_NPM_UNVERSIONED.is_match("npm install --global @angular/cli"));
    }

    #[test]
    fn npm_install_flag_first_version_pinned_not_flagged() {
        assert!(npm_install_has_version("npm install -g yarn@1.22.19"));
        assert!(npm_install_has_version("npm i -g yarn@1.22.19"));
    }

    #[test]
    fn pip_install_unversioned_detected() {
        assert!(SH_PIP_UNVERSIONED.is_match("pip install requests"));
        assert!(SH_PIP_UNVERSIONED.is_match("pip3 install flask"));
    }

    #[test]
    fn pip_install_version_pinned_not_flagged() {
        assert!(!SH_PIP_UNVERSIONED.is_match("pip install requests==2.31.0"));
    }

    #[test]
    fn pip_install_requirements_not_flagged() {
        assert!(!SH_PIP_UNVERSIONED.is_match("pip install -r requirements.txt"));
    }

    #[test]
    fn pip_install_flag_first_detected() {
        assert!(SH_PIP_UNVERSIONED.is_match("pip install -U requests"));
        assert!(SH_PIP_UNVERSIONED.is_match("pip3 install --upgrade flask"));
    }

    #[test]
    fn pip_install_flag_first_versioned_recognized() {
        assert!(pip_install_has_version("pip install -U requests==2.31.0"));
        assert!(pip_install_has_version(
            "pip install --no-cache-dir -r requirements.txt"
        ));
    }

    #[test]
    fn cargo_install_flag_first_detected() {
        // `--locked` respects the crate's lockfile but does not pin the
        // crate version itself.
        assert!(SH_CARGO_INSTALL_UNVERSIONED.is_match("cargo install --locked cargo-audit"));
        assert!(!cargo_install_has_version(
            "cargo install --locked cargo-audit"
        ));
        assert!(cargo_install_has_version(
            "cargo install --locked cargo-audit@0.21.0"
        ));
    }

    #[test]
    fn gem_install_flag_first_detected() {
        assert!(SH_GEM_INSTALL_UNVERSIONED.is_match("gem install -N rails"));
    }

    // ── JavaScript patterns ─────────────────────────────────────────────

    #[test]
    fn js_fetch_latest_detected() {
        assert!(
            JS_FETCH_LATEST
                .is_match(r#"fetch("https://api.github.com/repos/o/r/releases/latest")"#)
        );
    }

    #[test]
    fn js_exec_spawn_curl_detected() {
        assert!(JS_EXEC_SPAWN_CURL.is_match(r#"exec("curl -L https://example.com")"#));
        assert!(JS_EXEC_SPAWN_CURL.is_match(r#"execSync(`curl ${url}`)"#));
        assert!(JS_EXEC_SPAWN_CURL.is_match(r#"spawn("curl", ["-L", url])"#));
        assert!(JS_EXEC_SPAWN_CURL.is_match(r#"spawnSync("wget", [url])"#));
    }

    // ── Docker patterns ─────────────────────────────────────────────────

    #[test]
    fn docker_from_latest_detected() {
        assert!(DOCKER_FROM_LATEST.is_match("FROM ubuntu:latest"));
        assert!(DOCKER_FROM_LATEST.is_match("FROM node:latest AS builder"));
    }

    #[test]
    fn docker_from_untagged_detected() {
        assert!(DOCKER_FROM_UNTAGGED.is_match("FROM ubuntu AS builder"));
        assert!(DOCKER_FROM_UNTAGGED.is_match("FROM node "));
    }

    #[test]
    fn docker_from_tagged_not_untagged() {
        assert!(!DOCKER_FROM_UNTAGGED.is_match("FROM ubuntu:22.04"));
        assert!(!DOCKER_FROM_UNTAGGED.is_match("FROM ubuntu:latest"));
        assert!(!DOCKER_FROM_UNTAGGED.is_match(
            "FROM ubuntu@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        ));
    }

    #[test]
    fn docker_from_pinned_not_flagged() {
        assert!(!DOCKER_FROM_LATEST.is_match("FROM ubuntu:22.04"));
        assert!(DOCKER_FROM_DIGEST.is_match(
            "FROM ubuntu@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        ));
    }

    #[test]
    fn docker_from_platform_flag_detected() {
        // A `--platform` flag must not hide the image reference.
        assert!(DOCKER_FROM_LATEST.is_match("FROM --platform=linux/amd64 node:latest"));
        assert!(DOCKER_FROM_UNTAGGED.is_match("FROM --platform=$BUILDPLATFORM ubuntu"));
        assert!(!DOCKER_FROM_UNTAGGED.is_match("FROM --platform=linux/amd64 ubuntu:24.04"));
        assert!(DOCKER_FROM_DIGEST.is_match(
            "FROM --platform=linux/arm64 ubuntu@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        ));
        assert_eq!(
            dockerfile_from_base("FROM --platform=linux/amd64 ubuntu:24.04"),
            Some("ubuntu:24.04".to_string())
        );
    }

    #[test]
    fn docker_run_curl_detected() {
        assert!(DOCKER_RUN_CURL.is_match("RUN curl -L https://example.com/install.sh | bash"));
    }

    #[test]
    fn docker_add_url_detected() {
        assert!(DOCKER_ADD_URL.is_match("ADD https://example.com/install.tar.gz /tmp/"));
        assert!(DOCKER_ADD_URL.is_match("ADD http://example.com/foo.zip /opt/"));
    }

    #[test]
    fn docker_add_url_with_chown_detected() {
        assert!(
            DOCKER_ADD_URL.is_match("ADD --chown=user:group https://example.com/tool.tgz /opt/")
        );
    }

    #[test]
    fn docker_add_local_not_matched() {
        assert!(!DOCKER_ADD_URL.is_match("ADD ./local.tar.gz /opt/"));
        assert!(!DOCKER_ADD_URL.is_match("ADD context/* /app/"));
    }

    #[test]
    fn docker_add_case_insensitive() {
        assert!(DOCKER_ADD_URL.is_match("add https://example.com/tool.tgz /opt/"));
    }

    // ── Dockerfile stage helpers ───────────────────────────────────────

    #[test]
    fn dockerfile_stage_alias_extracts_lowercased_name() {
        assert_eq!(
            dockerfile_stage_alias("FROM golang:1.21 AS builder").as_deref(),
            Some("builder")
        );
        // Case-insensitive keyword, lowercased result.
        assert_eq!(
            dockerfile_stage_alias("from node:20 as Builder").as_deref(),
            Some("builder")
        );
        // Tolerates a leading --platform flag.
        assert_eq!(
            dockerfile_stage_alias("FROM --platform=$BUILDPLATFORM golang:1.21 AS web").as_deref(),
            Some("web")
        );
    }

    #[test]
    fn dockerfile_stage_alias_none_without_as() {
        assert_eq!(dockerfile_stage_alias("FROM ubuntu:22.04"), None);
        assert_eq!(dockerfile_stage_alias("RUN echo hello"), None);
    }

    #[test]
    fn dockerfile_from_base_extracts_lowercased_base() {
        assert_eq!(
            dockerfile_from_base("FROM ubuntu:22.04").as_deref(),
            Some("ubuntu:22.04")
        );
        assert_eq!(
            dockerfile_from_base("FROM scratch").as_deref(),
            Some("scratch")
        );
        assert_eq!(
            dockerfile_from_base("FROM builder AS final").as_deref(),
            Some("builder")
        );
        assert_eq!(dockerfile_from_base("RUN echo hello"), None);
    }

    // ── PowerShell patterns ────────────────────────────────────────────

    #[test]
    fn powershell_iwr_latest_detected() {
        assert!(
            SH_IWR_LATEST
                .is_match(r#"Invoke-WebRequest "https://example.com/releases/latest/tool""#)
        );
    }

    #[test]
    fn powershell_irm_latest_detected() {
        assert!(SH_IWR_LATEST.is_match(r#"irm "https://example.com/releases/latest/tool""#));
    }

    #[test]
    fn powershell_iwr_versioned_not_latest() {
        assert!(
            !SH_IWR_LATEST.is_match(
                r#"Invoke-WebRequest "https://example.com/releases/download/v1.2.3/tool""#
            )
        );
    }

    // ── Python patterns ────────────────────────────────────────────────

    #[test]
    fn python_requests_latest_detected() {
        assert!(
            PY_REQUESTS_LATEST
                .is_match(r#"requests.get("https://example.com/releases/latest/tool")"#)
        );
    }

    #[test]
    fn python_urllib_latest_detected() {
        assert!(
            PY_URLLIB_LATEST
                .is_match(r#"urllib.request.urlopen("https://example.com/releases/latest/tool")"#)
        );
    }

    #[test]
    fn python_subprocess_curl_detected() {
        assert!(PY_SUBPROCESS_CURL.is_match(r#"subprocess.run(["curl", "-L", url])"#));
    }

    #[test]
    fn python_requests_versioned_not_latest() {
        assert!(
            !PY_REQUESTS_LATEST
                .is_match(r#"requests.get("https://example.com/releases/download/v1.2.3/tool")"#)
        );
    }

    // ── Pipe-to-shell patterns ─────────────────────────────────────────

    #[test]
    fn pipe_shell_curl_to_sh() {
        assert!(SH_PIPE_SHELL.is_match("curl -sSL https://example.com/install.sh | sh"));
    }

    #[test]
    fn pipe_shell_curl_to_sudo_bash() {
        assert!(SH_PIPE_SHELL.is_match("curl -fsSL https://example.com/install.sh | sudo bash"));
    }

    #[test]
    fn pipe_shell_wget_to_sh_with_args() {
        assert!(
            SH_PIPE_SHELL.is_match("wget -qO- https://example.com/install.sh | sh -s -- --yes")
        );
    }

    #[test]
    fn pipe_shell_curl_to_python3() {
        assert!(SH_PIPE_SHELL.is_match("curl https://example.com/get.py | python3"));
    }

    #[test]
    fn pipe_shell_versioned_url_still_matches() {
        assert!(
            SH_PIPE_SHELL
                .is_match("curl -sSL https://example.com/releases/download/v1.2.3/install.sh | sh")
        );
    }

    #[test]
    fn pipe_shell_tee_not_matched() {
        assert!(!SH_PIPE_SHELL.is_match("curl https://example.com/file.sh | tee out.sh"));
    }

    #[test]
    fn pipe_shell_jq_not_matched() {
        assert!(!SH_PIPE_SHELL.is_match("curl https://api.example.com/data | jq ."));
    }

    #[test]
    fn pipe_shell_alternate_interpreters_matched() {
        for interp in ["node", "nodejs", "ruby", "perl", "pwsh", "powershell"] {
            assert!(
                SH_PIPE_SHELL.is_match(&format!("curl -fsSL https://x.example/i | {interp}")),
                "pipe to {interp} should be flagged as pipe-to-shell"
            );
        }
    }

    #[test]
    fn pipe_shell_wrapped_interpreter_matched() {
        // A path-qualified interpreter or an env/sudo/xargs wrapper must not evade detection.
        assert!(SH_PIPE_SHELL.is_match("curl -fsSL https://x.example/i | /bin/bash"));
        assert!(SH_PIPE_SHELL.is_match("curl -fsSL https://x.example/i | env bash"));
        assert!(SH_PIPE_SHELL.is_match("curl -fsSL https://x.example/i | xargs bash"));
        assert!(SH_PIPE_SHELL.is_match("wget -qO- https://x.example/i | sudo /usr/bin/python3"));
    }

    #[test]
    fn pipe_shell_non_interpreter_path_not_matched() {
        // A path that merely contains "node" but is not an interpreter must not match.
        assert!(!SH_PIPE_SHELL.is_match("curl https://x.example/i | node_modules/.bin/tool"));
    }

    #[test]
    fn proc_sub_bash_curl_matched() {
        assert!(SH_PROC_SUB_FETCH.is_match("bash <(curl https://example.com/install.sh)"));
    }

    #[test]
    fn proc_sub_sh_wget_matched() {
        assert!(SH_PROC_SUB_FETCH.is_match("sh <(wget -qO- https://example.com/install.sh)"));
    }

    #[test]
    fn proc_sub_not_fetch_not_matched() {
        assert!(!SH_PROC_SUB_FETCH.is_match("bash <(cat local.sh)"));
    }

    #[test]
    fn proc_sub_source_matched() {
        // `source <(curl …)` executes fetched content in the current shell.
        assert!(SH_PROC_SUB_FETCH.is_match("source <(curl -fsSL https://example.com/setup.sh)"));
    }

    #[test]
    fn pipe_through_intermediate_stage_matched() {
        assert!(SH_PIPE_SHELL.is_match("curl -fsSL https://example.com/install.sh | cat | sh"));
        assert!(SH_PIPE_SHELL.is_match(r"curl https://example.com/i.sh | tr -d '\r' | bash"));
    }

    #[test]
    fn pipe_multi_stage_without_shell_not_matched() {
        assert!(!SH_PIPE_SHELL.is_match("curl https://api.example.com/data | jq . | tee out.json"));
    }

    #[test]
    fn pipe_shell_jq_then_shell_still_matched() {
        // `jq` in the pipeline must not make a fetch that ultimately reaches a
        // shell look safe — pipe-to-shell still fires (and pre-empts the jq
        // data-fetch exemption).
        assert!(SH_PIPE_SHELL.is_match("curl https://x.example/c | jq -r .url | bash"));
    }

    // ── fetch_piped_to_jq ──────────────────────────────────────────────

    #[test]
    fn fetch_piped_to_jq_matches() {
        assert!(fetch_piped_to_jq(
            r#"curl -fsSL "https://crates.io/api/v1/crates/typos-cli" | jq -r '.crate.max_stable_version'"#
        ));
        assert!(fetch_piped_to_jq(
            "curl https://api.example.com/data | jq ."
        ));
        // No space after the pipe.
        assert!(fetch_piped_to_jq(
            "wget -qO- https://api.example.com/data |jq"
        ));
    }

    #[test]
    fn fetch_piped_to_jq_rejects_non_jq() {
        assert!(!fetch_piped_to_jq(
            "curl https://example.com/install.sh -o install.sh"
        ));
        assert!(!fetch_piped_to_jq(
            "curl https://api.example.com/d | grep foo"
        ));
        // `jq` must be a whole word, not a prefix of another command.
        assert!(!fetch_piped_to_jq(
            "curl https://api.example.com/d | jqlang"
        ));
    }

    #[test]
    fn cmd_sub_bash_c_curl_matched() {
        assert!(
            SH_CMD_SUB_FETCH.is_match(r#"bash -c "$(curl -fsSL https://example.com/install.sh)""#)
        );
    }

    #[test]
    fn cmd_sub_eval_wget_matched() {
        assert!(SH_CMD_SUB_FETCH.is_match(r#"eval "$(wget -qO- https://example.com/install.sh)""#));
    }

    #[test]
    fn cmd_sub_local_not_matched() {
        assert!(!SH_CMD_SUB_FETCH.is_match(r#"bash -c "$(pwd)""#));
    }

    #[test]
    fn cmd_sub_with_quoted_arg_matched() {
        // A quoted argument before the command substitution must not hide it.
        assert!(
            SH_CMD_SUB_FETCH
                .is_match(r#"bash --rcfile "x" -c "$(curl -fsSL https://example.com/install.sh)""#)
        );
    }

    #[test]
    fn cmd_sub_script_argument_not_matched() {
        // Fetched bytes passed as a script argument are not executed; `sh`
        // inside the filename must not satisfy the interpreter alternation.
        assert!(
            !SH_CMD_SUB_FETCH
                .is_match(r#"./notify.sh "$(curl -s https://api.example.com/status)""#)
        );
    }

    #[test]
    fn cmd_sub_flag_cluster_matched() {
        // `-c` folded into a flag cluster still executes the substitution.
        assert!(
            SH_CMD_SUB_FETCH.is_match(r#"bash -ec "$(curl -fsSL https://example.com/install.sh)""#)
        );
    }

    #[test]
    fn iwr_inside_word_not_matched() {
        // `irm` as a suffix of an ordinary word (confirm) must not fire.
        assert!(!SH_IWR_UNVERSIONED.is_match(r#"echo "Please confirm https://example.com/terms""#));
        assert!(!SH_IWR_LATEST.is_match("echo confirm https://example.com/releases/latest/x"));
    }

    #[test]
    fn curl_latest_at_end_of_line_matched() {
        assert!(SH_CURL_LATEST.is_match("curl -LO https://example.com/releases/latest"));
    }

    #[test]
    fn iex_iwr_matched() {
        assert!(SH_IEX_FETCH.is_match("iex (iwr https://example.com/install.ps1)"));
    }

    #[test]
    fn iex_downloadstring_matched() {
        assert!(SH_IEX_FETCH.is_match(
            r#"Invoke-Expression ((New-Object Net.WebClient).DownloadString("https://example.com/install.ps1"))"#
        ));
    }

    #[test]
    fn iex_invoke_restmethod_matched() {
        assert!(
            SH_IEX_FETCH.is_match("iex (Invoke-RestMethod -Uri https://example.com/install.ps1)")
        );
    }

    #[test]
    fn iex_without_fetch_not_matched() {
        assert!(!SH_IEX_FETCH.is_match("iex $scriptBlock"));
    }

    // ── Checksum verification ──────────────────────────────────────────

    #[test]
    fn checksum_sha256sum_detected() {
        assert!(has_checksum_verify("sha256sum --check checksums.txt"));
    }

    #[test]
    fn checksum_openssl_detected() {
        assert!(has_checksum_verify("openssl dgst -sha256 file.tar.gz"));
    }

    #[test]
    fn checksum_gpg_detected() {
        assert!(has_checksum_verify("gpg --verify file.sig file.tar.gz"));
    }

    #[test]
    fn checksum_gpg_with_intermediate_flags_detected() {
        // Flags between `gpg` and `--verify` must not defeat recognition.
        assert!(has_checksum_verify(
            "gpg --batch --verify file.sig file.tar.gz"
        ));
    }

    #[test]
    fn checksum_cosign_and_minisign_detected() {
        assert!(has_checksum_verify(
            "cosign verify-blob --signature s.sig artifact"
        ));
        assert!(has_checksum_verify("minisign -V -m file.tar.gz"));
    }

    #[test]
    fn checksum_powershell_detected() {
        assert!(has_checksum_verify(
            "Get-FileHash -Algorithm SHA256 file.tar.gz"
        ));
    }

    #[test]
    fn no_checksum() {
        assert!(!has_checksum_verify("echo done"));
    }

    // ── git clone patterns ─────────────────────────────────────────────

    #[test]
    fn git_clone_basic_detected() {
        assert!(SH_GIT_CLONE.is_match("git clone https://github.com/org/repo"));
    }

    #[test]
    fn git_clone_with_depth_detected() {
        assert!(SH_GIT_CLONE.is_match("git clone --depth 1 https://github.com/org/repo"));
    }

    #[test]
    fn git_clone_with_branch_detected() {
        assert!(SH_GIT_CLONE.is_match("git clone --branch main https://github.com/org/repo"));
    }

    #[test]
    fn git_clone_pinned_versioned_branch() {
        assert!(git_clone_has_pinned_ref(
            "git clone --branch v1.2.3 https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_pinned_short_flag() {
        assert!(git_clone_has_pinned_ref(
            "git clone -b v1.2.3 https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_pinned_no_v_prefix() {
        assert!(git_clone_has_pinned_ref(
            "git clone --branch 2.0.1 https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_pinned_release_branch_with_version() {
        assert!(git_clone_has_pinned_ref(
            "git clone --branch release/1.0.0 https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_pinned_depth_one_versioned() {
        assert!(git_clone_has_pinned_ref(
            "git clone --depth 1 --branch v1.2.3 https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_unpinned_main() {
        assert!(!git_clone_has_pinned_ref(
            "git clone --branch main https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_unpinned_master() {
        assert!(!git_clone_has_pinned_ref(
            "git clone -b master https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_unpinned_develop() {
        assert!(!git_clone_has_pinned_ref(
            "git clone -b develop https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_unpinned_feature_branch() {
        assert!(!git_clone_has_pinned_ref(
            "git clone --branch feature/my-feature https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_clone_no_branch_flag() {
        assert!(!git_clone_has_pinned_ref(
            "git clone https://github.com/org/repo"
        ));
    }

    #[test]
    fn git_checkout_sha_detected() {
        assert!(has_git_checkout_sha(
            "git checkout abcdef1234567890abcdef1234567890abcdef12"
        ));
    }

    #[test]
    fn git_checkout_branch_not_sha() {
        assert!(!has_git_checkout_sha("git checkout main"));
    }

    #[test]
    fn git_checkout_short_sha_not_matched() {
        assert!(!has_git_checkout_sha("git checkout abc1234"));
    }

    // ── cargo/gem install patterns ─────────────────────────────────────

    #[test]
    fn cargo_install_unversioned_detected() {
        assert!(SH_CARGO_INSTALL_UNVERSIONED.is_match("cargo install ripgrep"));
    }

    #[test]
    fn cargo_install_with_flags_detected() {
        assert!(SH_CARGO_INSTALL_UNVERSIONED.is_match("cargo install typos-cli --locked"));
        assert!(SH_CARGO_INSTALL_UNVERSIONED.is_match("cargo install cargo-deny --locked"));
    }

    #[test]
    fn cargo_install_no_args_not_flagged() {
        assert!(!SH_CARGO_INSTALL_UNVERSIONED.is_match("cargo install"));
    }

    #[test]
    fn gem_install_unversioned_detected() {
        assert!(SH_GEM_INSTALL_UNVERSIONED.is_match("gem install rubocop"));
    }

    #[test]
    fn gem_install_with_flags_detected() {
        assert!(SH_GEM_INSTALL_UNVERSIONED.is_match("gem install rubocop --no-document"));
    }

    #[test]
    fn gem_install_no_args_not_flagged() {
        assert!(!SH_GEM_INSTALL_UNVERSIONED.is_match("gem install"));
    }

    // ── pip/npm install with trailing flags ─────────────────────────────

    #[test]
    fn pip_install_with_flags_detected() {
        assert!(SH_PIP_UNVERSIONED.is_match("pip install requests --quiet"));
        assert!(SH_PIP_UNVERSIONED.is_match("pip3 install flask --user"));
    }

    #[test]
    fn npm_install_with_flags_detected() {
        assert!(SH_NPM_UNVERSIONED.is_match("npm install typescript --save-dev"));
        assert!(SH_NPM_UNVERSIONED.is_match("npm install @babel/core --save-dev"));
    }

    // ── version-pin check functions ────────────────────────────────────

    #[test]
    fn pip_version_pinned() {
        assert!(pip_install_has_version("pip install requests==2.31.0"));
        assert!(pip_install_has_version("pip install requests>=2.0"));
        assert!(pip_install_has_version("pip install requests~=2.31"));
        assert!(pip_install_has_version("pip install -r requirements.txt"));
    }

    #[test]
    fn pip_version_not_pinned() {
        assert!(!pip_install_has_version("pip install requests"));
        assert!(!pip_install_has_version("pip install requests --quiet"));
    }

    #[test]
    fn npm_version_pinned() {
        assert!(npm_install_has_version("npm install typescript@5.6.0"));
        assert!(npm_install_has_version("npm install @babel/core@1.0.0"));
    }

    #[test]
    fn npm_version_not_pinned() {
        assert!(!npm_install_has_version("npm install typescript"));
        assert!(!npm_install_has_version("npm install @babel/core"));
        assert!(!npm_install_has_version(
            "npm install typescript --save-dev"
        ));
    }

    #[test]
    fn cargo_version_pinned() {
        assert!(cargo_install_has_version("cargo install ripgrep@14.0.0"));
        assert!(cargo_install_has_version(
            "cargo install ripgrep --version 14.0.0"
        ));
    }

    #[test]
    fn cargo_version_not_pinned() {
        assert!(!cargo_install_has_version("cargo install ripgrep"));
        assert!(!cargo_install_has_version(
            "cargo install typos-cli --locked"
        ));
        assert!(!cargo_install_has_version(
            "cargo install cargo-deny --locked"
        ));
    }

    #[test]
    fn gem_version_pinned() {
        assert!(gem_install_has_version("gem install rubocop -v 1.0.0"));
        assert!(gem_install_has_version(
            "gem install rubocop --version 1.0.0"
        ));
    }

    #[test]
    fn gem_version_not_pinned() {
        assert!(!gem_install_has_version("gem install rubocop"));
        assert!(!gem_install_has_version(
            "gem install rubocop --no-document"
        ));
    }

    // ── npx patterns ───────────────────────────────────────────────────

    #[test]
    fn npx_unversioned_detected() {
        assert!(SH_NPX_UNVERSIONED.is_match("npx typescript"));
        assert!(SH_NPX_UNVERSIONED.is_match("npx create-react-app my-app"));
    }

    #[test]
    fn npx_scoped_unversioned_detected() {
        assert!(SH_NPX_UNVERSIONED.is_match("npx @angular/cli new my-app"));
    }

    #[test]
    fn npx_with_flags_detected() {
        assert!(SH_NPX_UNVERSIONED.is_match("npx -y create-react-app my-app"));
        assert!(SH_NPX_UNVERSIONED.is_match("npx --yes typescript"));
    }

    #[test]
    fn npx_version_pinned_helper_suppresses() {
        assert!(npx_has_version("npx typescript@5.6.0"));
        assert!(npx_has_version("npx @angular/cli@17.0.0 new my-app"));
        assert!(npx_has_version("npx -p typescript@5.6.0 tsc"));
        assert!(npx_has_version("npx --package=typescript@5.6.0 tsc"));
    }

    #[test]
    fn npx_version_not_pinned_helper() {
        assert!(!npx_has_version("npx typescript"));
        assert!(!npx_has_version("npx -y create-react-app"));
        assert!(!npx_has_version("npx @angular/cli"));
    }

    // ── brew install --HEAD ────────────────────────────────────────────

    #[test]
    fn brew_install_head_detected() {
        assert!(SH_BREW_HEAD.is_match("brew install ffmpeg --HEAD"));
        assert!(SH_BREW_HEAD.is_match("brew install ffmpeg --head"));
    }

    #[test]
    fn brew_install_head_with_other_flags_detected() {
        assert!(SH_BREW_HEAD.is_match("brew install --with-flags ffmpeg --HEAD"));
    }

    #[test]
    fn brew_install_without_head_not_flagged() {
        assert!(!SH_BREW_HEAD.is_match("brew install ffmpeg"));
        assert!(!SH_BREW_HEAD.is_match("brew install ffmpeg --with-chromaprint"));
    }

    // ── PowerShell Install-Module ──────────────────────────────────────

    #[test]
    fn ps_install_module_detected() {
        assert!(PS_INSTALL_MODULE_UNVERSIONED.is_match("Install-Module -Name Pester -Force"));
        assert!(PS_INSTALL_MODULE_UNVERSIONED.is_match("install-module PSReadLine"));
    }

    #[test]
    fn ps_install_script_detected() {
        assert!(
            PS_INSTALL_MODULE_UNVERSIONED.is_match("Install-Script -Name Get-WindowsAutoPilotInfo")
        );
    }

    #[test]
    fn ps_install_required_version_helper() {
        assert!(ps_install_has_required_version(
            "Install-Module -Name Pester -RequiredVersion 5.3.1"
        ));
        assert!(ps_install_has_required_version(
            "Install-Module Pester -requiredversion 5.3.1"
        ));
    }

    #[test]
    fn ps_install_minimum_version_not_accepted() {
        // -MinimumVersion alone is unbounded above — not a real pin.
        assert!(!ps_install_has_required_version(
            "Install-Module -Name Pester -MinimumVersion 5.0.0"
        ));
    }

    #[test]
    fn ps_install_no_version_flag() {
        assert!(!ps_install_has_required_version(
            "Install-Module -Name Pester -Force"
        ));
    }

    // ── pip install git+URL ────────────────────────────────────────────

    #[test]
    fn pip_install_git_url_detected() {
        assert!(
            SH_PIP_GIT_URL_UNVERSIONED
                .is_match("pip install git+https://github.com/owner/repo.git")
        );
        assert!(
            SH_PIP_GIT_URL_UNVERSIONED
                .is_match("pip3 install git+https://github.com/owner/repo.git")
        );
    }

    #[test]
    fn pip_install_git_url_with_flags_detected() {
        assert!(
            SH_PIP_GIT_URL_UNVERSIONED
                .is_match("pip install --user git+https://github.com/owner/repo.git")
        );
    }

    #[test]
    fn pip_install_git_url_versioned_or_sha_is_pinned() {
        // Version-like tag and a full 40-char SHA are immutable pins.
        assert!(pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git@v1.2.3"
        ));
        assert!(pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
        ));
        // The ref terminates at a `#egg=` fragment.
        assert!(pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git@v1.2.3#egg=foo"
        ));
        // A `user@host` userinfo prefix must not be mistaken for the ref.
        assert!(pip_git_url_has_ref(
            "pip install git+https://git@github.com/owner/repo.git@v1.2.3"
        ));
    }

    #[test]
    fn pip_install_git_url_branch_ref_is_not_pinned() {
        // A branch ref tracks HEAD — not a durable pin, so the rule still fires.
        assert!(!pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git@main"
        ));
        assert!(!pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git@develop"
        ));
        assert!(!pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git@feature/foo"
        ));
    }

    #[test]
    fn pip_install_git_url_without_ref() {
        assert!(!pip_git_url_has_ref(
            "pip install git+https://github.com/owner/repo.git"
        ));
        assert!(!pip_git_url_has_ref(
            "pip install --user git+https://github.com/owner/repo.git"
        ));
    }

    #[test]
    fn pip_install_plain_package_not_git_url() {
        assert!(!SH_PIP_GIT_URL_UNVERSIONED.is_match("pip install requests"));
        assert!(!SH_PIP_GIT_URL_UNVERSIONED.is_match("pip install requests==2.31.0"));
    }
}
