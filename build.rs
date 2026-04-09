use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=audited-actions");

    let dir = Path::new("audited-actions");
    let mut data: HashMap<String, Vec<String>> = HashMap::new();

    if dir.is_dir() {
        walk_dir(dir, dir, &mut data);
    }

    let json = serde_json::to_string(&data).unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("bundled_audited_actions.json");
    fs::write(dest, json).unwrap();
}

fn walk_dir(base: &Path, dir: &Path, data: &mut HashMap<String, Vec<String>>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir(base, &path, data);
        } else if path.extension().is_some_and(|e| e == "json")
            && let Some(key) = path_to_key(base, &path)
            && let Ok(content) = fs::read_to_string(&path)
            && let Ok(entries) = serde_json::from_str::<Vec<Entry>>(&content)
        {
            let shas: Vec<String> = entries.into_iter().map(|e| e.sha).collect();
            data.insert(key, shas);
        }
    }
}

/// Convert `audited-actions/actions/checkout.json` → `actions/checkout`
fn path_to_key(base: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(base).ok()?;
    let s = rel.with_extension("").to_string_lossy().to_string();
    Some(s.replace('\\', "/"))
}

#[derive(serde::Deserialize)]
struct Entry {
    sha: String,
}
