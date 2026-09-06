use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=audited-actions");

    let dir = Path::new("audited-actions");
    let mut data: HashMap<String, Vec<String>> = HashMap::new();

    assert!(dir.is_dir(), "audited-actions directory is missing");
    walk_dir(dir, dir, &mut data).unwrap_or_else(|error| panic!("{error}"));

    let json = serde_json::to_string(&data).unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("bundled_audited_actions.json");
    fs::write(dest, json).unwrap();
}

fn walk_dir(
    base: &Path,
    dir: &Path,
    data: &mut HashMap<String, Vec<String>>,
) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|error| format!("could not read {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("could not read {}: {error}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(base, &path, data)?;
        } else if path.extension().is_some_and(|e| e == "json")
            && let Some(key) = path_to_key(base, &path)
        {
            let content = fs::read_to_string(&path)
                .map_err(|error| format!("could not read {}: {error}", path.display()))?;
            let entries = serde_json::from_str::<Vec<Entry>>(&content)
                .map_err(|error| format!("{} contains invalid JSON: {error}", path.display()))?;
            let mut shas = Vec::with_capacity(entries.len());
            for entry in entries {
                if !is_full_sha(&entry.sha) {
                    return Err(format!(
                        "{} contains non-canonical SHA `{}`",
                        path.display(),
                        entry.sha
                    ));
                }
                shas.push(entry.sha.to_ascii_lowercase());
            }
            data.insert(key, shas);
        }
    }
    Ok(())
}

fn is_full_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Convert `audited-actions/actions/checkout.json` → `actions/checkout`
fn path_to_key(base: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(base).ok()?;
    let s = rel.with_extension("").to_string_lossy().to_string();
    // Windows yields `\`-separated relative paths; keys are always `/`-joined.
    Some(s.replace('\\', "/"))
}

#[derive(serde::Deserialize)]
struct Entry {
    sha: String,
}
