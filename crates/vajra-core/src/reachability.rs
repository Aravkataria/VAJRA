use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReachabilityResult {
    pub package_name: String,
    pub is_reachable: bool,
    pub call_sites: Vec<String>,
}

pub struct ReachabilityAnalyzer;

impl ReachabilityAnalyzer {
    pub fn analyze(root_dir: &Path) -> Vec<ReachabilityResult> {
        let mut imported_packages = HashMap::new();

        for entry in WalkDir::new(root_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("py") {
                    if let Ok(content) = fs::read_to_string(path) {
                        for line in content.lines() {
                            let trimmed = line.trim();
                            if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    let pkg = parts[1].split('.').next().unwrap_or("").to_string();
                                    imported_packages.entry(pkg).or_insert_with(Vec::new).push(format!("{}: {}", path.display(), trimmed));
                                }
                            }
                        }
                    }
                }
            }
        }

        imported_packages
            .into_iter()
            .map(|(package_name, call_sites)| ReachabilityResult {
                package_name,
                is_reachable: true,
                call_sites,
            })
            .collect()
    }
}
