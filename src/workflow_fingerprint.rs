use crate::workflow::{self, RefType};
use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde_norway::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::LazyLock;

const MASKED_SHA: &str = "0000000000000000000000000000000000000000";
const DOMAIN: &[u8] = b"pinprick-workflow-context-v1\0";
static ACTION_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$").unwrap()
});

fn action_names(actions: &[String]) -> Result<BTreeSet<&str>> {
    ensure!(
        !actions.is_empty(),
        "at least one action identity is required"
    );
    let mut names = BTreeSet::new();
    for action in actions {
        ensure!(
            ACTION_NAME.is_match(action)
                && action.split('/').all(|part| part != "." && part != ".."),
            "expected one literal owner/repo[/subpath] action identity"
        );
        ensure!(names.insert(action.as_str()), "duplicate action identity");
    }
    Ok(names)
}

/// v1 preserves every byte except full SHA pins and version-only comments on
/// the named step actions. The policy's sorted identities are bound into the
/// digest, so widening that policy requires a new reviewed fingerprint.
pub(crate) fn context_digest(content: &str, actions: &[String]) -> Result<String> {
    let names = action_names(actions)?;
    ensure!(
        workflow::scan_unsupported_uses(content).is_empty(),
        "unsupported workflow action syntax"
    );
    let mut expected: Value = serde_norway::from_str(content).context("parsing workflow")?;
    let jobs = expected
        .get_mut("jobs")
        .and_then(Value::as_mapping_mut)
        .context("workflow must contain a jobs mapping")?;
    let mut seen = BTreeSet::new();
    for (_, job) in jobs {
        if let Some(steps) = job.get_mut("steps") {
            mask_step_actions(steps, &names, &mut seen)?;
        }
    }
    ensure!(
        seen.iter().map(String::as_str).collect::<BTreeSet<_>>() == names,
        "each ignored action must occur as a SHA-pinned step action"
    );

    let mut replacements = BTreeMap::new();
    for action in workflow::scan_content(content) {
        if !names.contains(action.full_name().as_str()) {
            continue;
        }
        ensure!(
            action.ref_type == RefType::Sha && action.block_style,
            "expected a full SHA pin"
        );
        let mut line = action.raw_line.clone();
        let start = action.value_end - action.ref_string.len();
        ensure!(
            line.get(start..action.value_end) == Some(action.ref_string.as_str()),
            "action span does not match its source"
        );
        line.replace_range(start..action.value_end, MASKED_SHA);
        if let Some(comment) = action.tag_comment.as_deref()
            && semver::Version::parse(comment.strip_prefix('v').unwrap_or(comment)).is_ok()
        {
            // Only the version token changes; whitespace, the comment marker,
            // quotes, and any non-version comment remain part of the digest.
            let offset = action.value_end
                + line[action.value_end..]
                    .find('#')
                    .context("missing comment")?;
            let start =
                offset + 1 + line[offset + 1..].len() - line[offset + 1..].trim_start().len();
            line.replace_range(start..start + comment.len(), "v0.0.0");
        }
        ensure!(
            replacements.insert(action.line_number, line).is_none(),
            "ambiguous action line"
        );
    }
    let mut normalized = String::with_capacity(content.len());
    for (index, line) in content.split_inclusive('\n').enumerate() {
        if let Some(replacement) = replacements.get(&(index + 1)) {
            normalized.push_str(replacement);
            if line.ends_with("\r\n") {
                normalized.push_str("\r\n");
            } else if line.ends_with('\n') {
                normalized.push('\n');
            }
        } else {
            normalized.push_str(line);
        }
    }

    // The line scanner is deliberately broader than jobs.*.steps. Compare
    // parsed documents to refuse edits inside scripts, inputs, or aliased data.
    let actual: Value =
        serde_norway::from_str(&normalized).context("parsing normalized workflow")?;
    ensure!(
        actual == expected,
        "action spans change more than step action revisions"
    );
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for name in names {
        hash.update(name.as_bytes());
        hash.update(b"\0");
    }
    hash.update(b"\0");
    hash.update(normalized.as_bytes());
    let mut digest = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(digest, "{byte:02x}")?;
    }
    Ok(digest)
}

fn mask_step_actions(
    steps: &mut Value,
    names: &BTreeSet<&str>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    let steps = steps
        .as_sequence_mut()
        .context("steps must be a sequence")?;
    for step in steps {
        if let Some(value) = step.get_mut("uses")
            && let Some(action) = value
                .as_str()
                .and_then(workflow::parse_external_action_reference)
            && names.contains(action.full_name().as_str())
        {
            ensure!(
                action.ref_type == RefType::Sha,
                "ignored action must use a full SHA pin"
            );
            let name = action.full_name();
            *value = Value::String(format!("{name}@{MASKED_SHA}"));
            seen.insert(name);
        }
        if let Some(parallel) = step.get_mut("parallel") {
            mask_step_actions(parallel, names, seen)?;
        }
    }
    Ok(())
}

pub(crate) fn run(root: &Path, path: &str, actions: &[String], json: bool) -> Result<ExitCode> {
    let file = workflow::find_workflows(root)?
        .into_iter()
        .find(|file| workflow::display_path(file.path(), root) == path);
    let Some(file) = file else {
        bail!("workflow must name one discovered repository-relative workflow path");
    };
    let content = workflow::read_workflow(&file)?;
    let digest = context_digest(&content, actions)?;
    let names = action_names(actions)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "workflow": path,
                "workflow_context_sha256": digest,
                "ignore_action_revisions": names,
            })
        );
    } else {
        println!("workflow = {}", serde_json::to_string(path)?);
        println!("workflow-context-sha256 = {digest:?}");
        println!(
            "ignore-action-revisions = {}",
            serde_json::to_string(&names)?
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "1111111111111111111111111111111111111111";

    fn source() -> String {
        format!(
            "on: push\njobs:\n  scan:\n    steps:\n      - uses: actions/checkout@{SHA} # v7.0.1\n      - run: echo safe\n"
        )
    }

    fn digest(source: &str) -> Result<String> {
        context_digest(source, &["actions/checkout".into()])
    }

    #[test]
    fn preserves_every_byte_outside_pins_and_full_version_tokens() {
        let original = source();
        let expected = digest(&original).unwrap();
        assert_eq!(
            expected,
            "a26937392f716836c7a2781a8074639d4ba162bee0fea2bf3eada217d03dc3ef"
        );
        assert_eq!(
            digest(&original.replace(SHA, &"a".repeat(40))).unwrap(),
            expected
        );
        assert_eq!(
            digest(&original.replace("v7.0.1", "8.1.0-beta.1+build.2")).unwrap(),
            expected
        );
        for changed in [
            original.replace("# v7.0.1", "# v7.0.1 retained note"),
            original.replace("# v7.0.1", "# v7"),
            original.replace("# v7.0.1", "# v7.0"),
            original.replace(" #", "  #"),
            original.replace("# v", "#  v"),
            original.replace("# v7.0.1", "# v7.0.1 "),
            original.replace('\n', "\r\n"),
            original.trim_end().to_string(),
            format!("{original}# unrelated comment\n"),
            original.replace("echo safe", "echo different"),
        ] {
            assert_ne!(digest(&changed).unwrap(), expected, "{changed}");
        }
    }

    #[test]
    fn handles_quoted_pins_crlf_and_parallel_steps() {
        let original = source();
        for source in [
            original.replace(
                &format!("actions/checkout@{SHA}"),
                &format!("'actions/checkout@{SHA}'"),
            ),
            original.replace(
                &format!("actions/checkout@{SHA}"),
                &format!("\"actions/checkout@{SHA}\""),
            ),
            original.replace('\n', "\r\n"),
            original.replace("      - uses:", "      - parallel:\n          - uses:"),
        ] {
            let updated = source
                .replace(SHA, &"b".repeat(40))
                .replace("v7.0.1", "v8.0.0");
            assert_eq!(digest(&source).unwrap(), digest(&updated).unwrap());
        }
    }

    #[test]
    fn scripts_and_inputs_cannot_masquerade_as_action_references() {
        for suffix in [
            format!("      - run: |\n          uses: actions/checkout@{SHA} # v7.0.1\n"),
            format!("      - run: >-\n          uses: actions/checkout@{SHA} # v7.0.1\n"),
            format!(
                "      - run: 'echo\n          uses: actions/checkout@{SHA}\n          done'\n"
            ),
            format!(
                "      - run: \"echo\n          uses: actions/checkout@{SHA}\n          done\"\n"
            ),
            format!("      - with:\n          uses: actions/checkout@{SHA} # v7.0.1\n"),
        ] {
            let original = format!("{}{suffix}", source());
            let changed_suffix = suffix
                .replace(SHA, &"c".repeat(40))
                .replace("v7.0.1", "v9.0.0");
            let changed = format!("{}{changed_suffix}", source());
            if let (Ok(before), Ok(after)) = (digest(&original), digest(&changed)) {
                assert_ne!(before, after, "{suffix}");
            }
        }
    }

    #[test]
    fn unsupported_or_ambiguous_yaml_cannot_authorize_context_acceptance() {
        for source in [
            source()
                .replace(
                    "      - uses: actions/checkout",
                    "      - { uses: actions/checkout",
                )
                .replace(" # v7.0.1", " }"),
            source().replace("on: push", "on: push\non: pull_request"),
            source().replace("steps:", "steps: ["),
            source().replace("uses:", "\"u\\u0073es\":"),
            format!(
                "reference: &pin actions/checkout@{SHA}\njobs:\n  scan:\n    steps:\n      - uses: *pin\n"
            ),
            format!(
                "jobs:\n  scan:\n    steps:\n      - uses: &pin actions/checkout@{SHA}\n        with:\n          script: *pin\n"
            ),
        ] {
            assert!(digest(&source).is_err(), "{source}");
        }
    }

    #[test]
    fn action_list_is_exact_unique_present_and_bound_into_digest() {
        let source = format!(
            "{}      - uses: actions/upload-artifact@{SHA} # v7.0.1\n",
            source()
        );
        let both = vec!["actions/checkout".into(), "actions/upload-artifact".into()];
        let reverse = both.iter().rev().cloned().collect::<Vec<_>>();
        let all = context_digest(&source, &both).unwrap();
        assert_eq!(all, context_digest(&source, &reverse).unwrap());
        assert_ne!(all, digest(&source).unwrap());
        let updated = source.replace(
            &format!("upload-artifact@{SHA}"),
            &format!("upload-artifact@{}", "d".repeat(40)),
        );
        assert_eq!(all, context_digest(&updated, &both).unwrap());
        assert_ne!(digest(&source).unwrap(), digest(&updated).unwrap());
        for names in [
            vec![],
            vec!["actions/*".into()],
            vec!["actions/../checkout".into()],
            vec!["actions/checkout@main".into()],
            vec!["./act".into()],
            vec!["actions/missing".into()],
            vec!["actions/checkout".into(), "actions/checkout".into()],
        ] {
            assert!(context_digest(&source, &names).is_err(), "{names:?}");
        }
    }
}
