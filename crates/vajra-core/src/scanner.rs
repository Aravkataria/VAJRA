use crate::models::Finding;
use rayon::prelude::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct Rule {
    pub id: &'static str,
    pub vuln_type: &'static str,
    pub severity: &'static str,
    pub pattern: Regex,
    pub message: &'static str,
}

pub struct CoreScanner {
    rules: Vec<Rule>,
}

impl CoreScanner {
    pub fn new() -> Self {
        let rules = vec![
            Rule {
                id: "cmd_eval",
                vuln_type: "command_injection",
                severity: "CRITICAL",
                pattern: Regex::new(r"\beval\s*\(").unwrap(),
                message: "Dynamic evaluation sink 'eval()' with untrusted expression executes arbitrary code.",
            },
            Rule {
                id: "cmd_os_system",
                vuln_type: "command_injection",
                severity: "CRITICAL",
                pattern: Regex::new(r"\bos\.system\s*\(").unwrap(),
                message: "System shell execution sink 'os.system()' vulnerable to arbitrary shell command injection.",
            },
            Rule {
                id: "cmd_subprocess_shell",
                vuln_type: "command_injection",
                severity: "CRITICAL",
                pattern: Regex::new(r"\bsubprocess\.(?:run|Popen|check_output|call)\s*\([^)]*shell\s*=\s*True").unwrap(),
                message: "Subprocess executed with shell=True allows untrusted metacharacter command execution.",
            },
            Rule {
                id: "deser_pickle",
                vuln_type: "insecure_deserialization",
                severity: "HIGH",
                pattern: Regex::new(r"\bpickle\.loads?\s*\(").unwrap(),
                message: "Insecure pickle deserialization executes arbitrary Python bytecode payloads.",
            },
            Rule {
                id: "deser_yaml",
                vuln_type: "insecure_deserialization",
                severity: "HIGH",
                pattern: Regex::new(r"\byaml\.load\s*\([^,)]+\)").unwrap(),
                message: "Arbitrary object instantiation via unconstrained yaml.load() without SafeLoader.",
            },
            Rule {
                id: "sqli_execute",
                vuln_type: "sql_injection",
                severity: "CRITICAL",
                pattern: Regex::new(r#"cursor\.execute\s*\(\s*f?['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*(?:%s|%d|\{[^}]+\})"#).unwrap(),
                message: "Unparameterized dynamic SQL query construction vulnerable to SQL injection.",
            },
            Rule {
                id: "secrets_hardcoded",
                vuln_type: "hardcoded_credentials",
                severity: "HIGH",
                pattern: Regex::new(r#"(?:API_KEY|SECRET_KEY|PASSWORD|TOKEN|AUTH_KEY)\s*=\s*['"][a-zA-Z0-9_\-]{8,}['"]"#).unwrap(),
                message: "Hardcoded cryptographic secret or API credential detected in source tree.",
            },
            Rule {
                id: "path_traversal",
                vuln_type: "path_traversal",
                severity: "HIGH",
                pattern: Regex::new(r#"(?:open|send_file)\s*\(\s*(?:request\.(?:args|form)|os\.path\.join\([^)]*request\.)"#).unwrap(),
                message: "Unsanitized user input concatenated into filesystem path operation (Path Traversal).",
            },
        ];

        CoreScanner { rules }
    }

    pub fn scan_directory(&self, root_dir: &Path) -> (Vec<Finding>, usize) {
        let files: Vec<PathBuf> = WalkDir::new(root_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| {
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                matches!(ext, "py" | "js" | "ts" | "c" | "cpp" | "go" | "rs" | "java" | "php" | "cs")
            })
            .collect();

        let files_count = files.len();

        let findings: Vec<Finding> = files
            .par_iter()
            .flat_map(|file_path| self.scan_file(file_path, root_dir))
            .collect();

        (findings, files_count)
    }

    pub fn scan_file(&self, file_path: &Path, base_dir: &Path) -> Vec<Finding> {
        let mut file_findings = Vec::new();
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return file_findings,
        };

        let rel_path = file_path
            .strip_prefix(base_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .replace('\\', "/");

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            for rule in &self.rules {
                if let Some(mat) = rule.pattern.find(line) {
                    file_findings.push(Finding {
                        file: rel_path.clone(),
                        line: line_num,
                        column: mat.start() + 1,
                        vulnerability_type: rule.vuln_type.to_string(),
                        severity: rule.severity.to_string(),
                        message: rule.message.to_string(),
                        snippet: line.trim().to_string(),
                    });
                }
            }
        }

        file_findings
    }
}
