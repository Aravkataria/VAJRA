// src-tauri/src/commands.rs
use std::path::Path;
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

    let scanner = CoreScanner::new();
    let report = scanner.scan_directory(target);
    Ok(report)
}

#[tauri::command]
pub fn run_mutation_analysis(original: String, patch: String) -> Result<MutationReport, String> {
    let report = PatchMutationEngine::evaluate(&original, &patch);
    Ok(report)
}

#[tauri::command]
pub fn run_fuzz_analysis(code: String) -> Result<FuzzCorpusReport, String> {
    let report = FuzzCorpusGenerator::generate_corpus(&code);
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
