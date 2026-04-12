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

re!(SH_CURL_LATEST, r#"curl\b.*[/=]latest[/\s"]"#);
re!(SH_WGET_LATEST, r#"wget\b.*[/=]latest[/\s"]"#);
re!(SH_GH_RELEASE_LATEST, r"gh\s+release\s+download\s");
re!(SH_CURL_UNVERSIONED, r#"curl\b.*https?://[^\s"']+"#);
re!(SH_WGET_UNVERSIONED, r#"wget\b.*https?://[^\s"']+"#);
re!(
    SH_PIP_UNVERSIONED,
    r"pip3?\s+install\s+[a-zA-Z][a-zA-Z0-9_-]*\s*$"
);
re!(
    SH_NPM_UNVERSIONED,
    r"npm\s+install\s+(@[a-zA-Z][a-zA-Z0-9_-]*/)?[a-zA-Z][a-zA-Z0-9_-]*\s*$"
);
re!(SH_GO_INSTALL_LATEST, r"go\s+install\s+\S+@latest");
re!(
    SH_IWR_LATEST,
    r#"(?i)(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b.*[/=]latest[/\s"]"#
);
re!(
    SH_IWR_UNVERSIONED,
    r#"(?i)(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b.*https?://[^\s"']+"#
);

re!(
    SH_PIPE_SHELL,
    r"(?i)\b(curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(bash|sh|zsh|dash|ash|ksh|fish|python3?)\b"
);
re!(
    SH_PROC_SUB_FETCH,
    r"(?i)\b(bash|sh|zsh|dash|ash|ksh|fish|python3?)\s+<\(\s*(curl|wget)\b"
);
re!(
    SH_CMD_SUB_FETCH,
    r#"(?i)\b(bash|sh|zsh|eval)\b[^"']*["']?\$\(\s*(curl|wget)\b"#
);
re!(
    SH_IEX_FETCH,
    r"(?i)\b(iex|Invoke-Expression)\b.*\b(iwr|Invoke-WebRequest|Invoke-RestMethod|irm|DownloadString)\b"
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
            description: "go install @latest — not version-pinned",
        },
        Pattern {
            regex: &SH_IWR_LATEST,
            severity: Severity::High,
            category: Category::ShellFetch,
            description: "PowerShell fetching from a 'latest' URL — can change without notice",
        },
        Pattern {
            regex: &SH_PIP_UNVERSIONED,
            severity: Severity::Low,
            category: Category::ShellFetch,
            description: "pip install without version pin",
        },
        Pattern {
            regex: &SH_NPM_UNVERSIONED,
            severity: Severity::Low,
            category: Category::ShellFetch,
            description: "npm install without version pin",
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
// produces a single high-severity finding. Not subject to checksum downgrade —
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
re!(JS_EXEC_CURL, r"exec\w*\s*\(.*\bcurl\b");
re!(JS_CHILD_PROC_CURL, r"child_process.*\bcurl\b");
re!(JS_FETCH_URL, r#"fetch\s*\(\s*["'`]https?://"#);
re!(JS_AXIOS_URL, r#"axios\.\w+\s*\(\s*["'`]https?://"#);

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
            regex: &JS_EXEC_CURL,
            severity: Severity::High,
            category: Category::JavaScriptFetch,
            description: "exec() shelling out to curl — runtime fetch bypasses pinning",
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
    ]
});

// ── Docker patterns ─────────────────────────────────────────────────────────

re!(DOCKER_FROM_LATEST, r"(?i)^FROM\s+\S+:latest\b");
re!(
    DOCKER_FROM_UNTAGGED,
    r"(?i)^FROM\s+[a-z][a-z0-9._/-]*(\s|$)"
);
re!(DOCKER_FROM_DIGEST, r"(?i)^FROM\s+\S+@sha256:");
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
    r"(?i)(sha256sum|sha512sum|shasum|openssl\s+dgst|gpg\s+--verify|Get-FileHash)"
);

/// Check if a line contains a checksum verification command.
pub fn has_checksum_verify(line: &str) -> bool {
    CHECKSUM_VERIFY.is_match(line)
}

// ── URL version detection ───────────────────────────────────────────────────

static VERSION_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[/=]v?\d+(\.\d+)+[/\s"]"#).unwrap());

/// Check if a URL-like string contains a version segment.
pub fn url_has_version(s: &str) -> bool {
    VERSION_SEGMENT.is_match(s)
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

/// Extract the first URL from a line.
pub fn extract_url(line: &str) -> Option<&str> {
    static URL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"https?://[^\s"'`)>]+"#).unwrap());
    URL_RE.find(line).map(|m| m.as_str())
}

/// Check if a `gh release download` line has a version tag argument.
/// `gh release download v1.2.3 --pattern ...` is pinned (positional).
/// `gh release download --tag v1.2.3 --pattern ...` is pinned (flag).
/// `gh release download --pattern ...` grabs latest.
pub fn gh_release_has_tag(line: &str) -> bool {
    static GH_RELEASE_TAG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"gh\s+release\s+download\s+(v?\d|--tag\s+v?\d)").unwrap());
    GH_RELEASE_TAG.is_match(line)
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

    // ── extract_url ─────────────────────────────────────────────────────

    #[test]
    fn extract_url_from_curl() {
        let line = r#"curl -L "https://example.com/file.tar.gz" -o out"#;
        assert_eq!(extract_url(line), Some("https://example.com/file.tar.gz"));
    }

    #[test]
    fn extract_url_single_quotes() {
        let line = "wget 'https://example.com/file'";
        assert_eq!(extract_url(line), Some("https://example.com/file"));
    }

    #[test]
    fn no_url() {
        assert!(extract_url("echo hello world").is_none());
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

    // ── JavaScript patterns ─────────────────────────────────────────────

    #[test]
    fn js_fetch_latest_detected() {
        assert!(
            JS_FETCH_LATEST
                .is_match(r#"fetch("https://api.github.com/repos/o/r/releases/latest")"#)
        );
    }

    #[test]
    fn js_exec_curl_detected() {
        assert!(JS_EXEC_CURL.is_match(r#"exec("curl -L https://example.com")"#));
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
    fn checksum_powershell_detected() {
        assert!(has_checksum_verify(
            "Get-FileHash -Algorithm SHA256 file.tar.gz"
        ));
    }

    #[test]
    fn no_checksum() {
        assert!(!has_checksum_verify("echo done"));
    }
}
