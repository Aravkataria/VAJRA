use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub vulnerability_type: String,
    pub severity: String,
    pub message: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub engine: String,
    pub version: String,
    pub target_path: String,
    pub files_scanned: usize,
    pub total_findings: usize,
    pub duration_ms: u128,
    pub findings: Vec<Finding>,
}
