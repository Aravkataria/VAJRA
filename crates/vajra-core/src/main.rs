use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;
use vajra_core::{
    CoreScanner, FuzzCorpusGenerator, GitHistoryArchaeologist, PatchMutationEngine,
    ReachabilityAnalyzer, ScanReport,
};

#[derive(Parser)]
#[command(name = "vajra-core")]
#[command(about = "High-performance multithreaded cyber-reasoning analysis engine for VAJRA", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Multi-threaded repository AST sink scan
    Scan {
        /// Path to target codebase directory
        path: PathBuf,
        /// Output results as JSON
        #[arg(long, default_value_t = true)]
        json: bool,
    },
    /// Generate high-throughput boundary fuzzing corpus
    Fuzz {
        /// Vulnerability sink type (e.g. command_injection, insecure_deserialization)
        vuln_type: String,
        /// Fuzz nesting depth
        #[arg(long, default_value_t = 5)]
        depth: usize,
    },
    /// Synthesize adversarial mutant variants for candidate patch verification
    Mutate {
        /// Code of candidate patch
        code: String,
        /// Vulnerability type
        vuln_type: String,
    },
    /// Line-level causal git commit and intent archaeological investigation
    GitBlame {
        /// Repository directory path
        repo_path: String,
        /// Relative file path
        file: String,
        /// Line number
        line: usize,
        /// Vulnerability type
        vuln_type: String,
    },
    /// Analyze package import and call-graph reachability
    Reachability {
        /// Path to target codebase directory
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, json } => {
            let start = Instant::now();
            let scanner = CoreScanner::new();
            let (findings, files_count) = scanner.scan_directory(&path);
            let duration = start.elapsed().as_millis();

            let report = ScanReport {
                engine: "vajra-core-rust".to_string(),
                version: "2.4.0".to_string(),
                target_path: path.to_string_lossy().to_string(),
                files_scanned: files_count,
                total_findings: findings.len(),
                duration_ms: duration,
                findings,
            };

            if json {
                let json_output = serde_json::to_string_pretty(&report).unwrap();
                println!("{}", json_output);
            } else {
                println!("VAJRA-CORE (RUST ENGINE v2.4.0)");
                println!("Scanned {} files in {}ms", files_count, duration);
                println!("Discovered {} vulnerabilities:", report.total_findings);
                for f in &report.findings {
                    println!("  [{}] {}:{} - {}", f.severity, f.file, f.line, f.message);
                }
            }
        }
        Commands::Fuzz { vuln_type, depth } => {
            let report = FuzzCorpusGenerator::generate_corpus(&vuln_type, depth);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        Commands::Mutate { code, vuln_type } => {
            let report = PatchMutationEngine::generate_mutants(&code, &vuln_type);
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        Commands::GitBlame {
            repo_path,
            file,
            line,
            vuln_type,
        } => {
            let intent = GitHistoryArchaeologist::investigate_line(&repo_path, &file, line, &vuln_type);
            println!("{}", serde_json::to_string_pretty(&intent).unwrap());
        }
        Commands::Reachability { path } => {
            let results = ReachabilityAnalyzer::analyze(&path);
            println!("{}", serde_json::to_string_pretty(&results).unwrap());
        }
    }
}
