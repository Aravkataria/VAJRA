// src-tauri/src/lib.rs
pub mod commands;

use commands::{scan_directory, run_mutation_analysis, run_fuzz_analysis, get_system_info};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            scan_directory,
            run_mutation_analysis,
            run_fuzz_analysis,
            get_system_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running VAJRA desktop application");
}
