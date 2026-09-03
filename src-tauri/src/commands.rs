// src-tauri/src/commands.rs
use std::path::Path;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use vajra_core::{
    scanner::CoreScanner,
    mutation::PatchMutationEngine,
    fuzzer::FuzzCorpusGenerator,
    models::ScanReport,
    mutation::MutationReport,
    fuzzer::FuzzCorpusReport,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemTelemetry {
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub engine: String,
    pub cores: usize,
}

#[tauri::command]
pub fn scan_directory(path: String) -> Result<ScanReport, String> {
    let target = Path::new(&path);
    if !target.exists() {
        return Err(format!("Target directory does not exist: {}", path));
    }

    let start = Instant::now();
    let scanner = CoreScanner::new();
    let (findings, files_scanned) = scanner.scan_directory(target);
    let duration_ms = start.elapsed().as_millis();

    Ok(ScanReport {
        engine: "VAJRA-Core Native Rayon Engine (Rust)".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        target_path: path,
        files_scanned,
        total_findings: findings.len(),
        duration_ms,
        findings,
    })
}

#[tauri::command]
pub fn run_mutation_analysis(patched_code: String, vuln_type: String) -> Result<MutationReport, String> {
    let report = PatchMutationEngine::generate_mutants(&patched_code, &vuln_type);
    Ok(report)
}

#[tauri::command]
pub fn run_fuzz_analysis(vuln_type: String, depth: usize) -> Result<FuzzCorpusReport, String> {
    let report = FuzzCorpusGenerator::generate_corpus(&vuln_type, depth);
    Ok(report)
}

#[tauri::command]
pub fn get_system_info() -> SystemTelemetry {
    SystemTelemetry {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        engine: "VAJRA-Core Native Rayon Engine (Rust)".to_string(),
        cores: num_cpus(),
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
