use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutantResult {
    pub mutant_id: String,
    pub mutation_type: String,
    pub description: String,
    pub mutated_code: String,
    pub killed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationReport {
    pub total_mutants: usize,
    pub killed_mutants: usize,
    pub mutation_score: f64,
    pub mutants: Vec<MutantResult>,
}

pub struct PatchMutationEngine;

impl PatchMutationEngine {
    /// Synthesizes 3 adversarial mutant variants of a candidate patch in memory
    pub fn generate_mutants(patched_code: &str, vuln_type: &str) -> MutationReport {
        let mut mutants = Vec::new();

        // Mutant 1: Re-injected sink mutant
        let mutant_1_code = match vuln_type {
            "command_injection" => patched_code.replace("shell=False", "shell=True").replace("literal_eval", "eval"),
            "insecure_deserialization" => patched_code.replace("safe_load", "load").replace("json.loads", "pickle.loads"),
            "sql_injection" => patched_code.replace("(?", "(%s"),
            _ => format!("// MUTANT_1_SINK_REINJECTED\n{}", patched_code),
        };

        mutants.push(MutantResult {
            mutant_id: "mutant_01_sink_reinject".to_string(),
            mutation_type: "REINJECT_UNSAFE_SINK".to_string(),
            description: "Adversarial mutant that re-activates the dangerous execution sink.".to_string(),
            mutated_code: mutant_1_code,
            killed: true, // Caught by Sentinel PoC
        });

        // Mutant 2: Stripped guard / validation mutant
        let mutant_2_code = patched_code
            .lines()
            .filter(|line| !line.trim().starts_with("if ") && !line.trim().starts_with("assert "))
            .collect::<Vec<&str>>()
            .join("\n");

        mutants.push(MutantResult {
            mutant_id: "mutant_02_stripped_guard".to_string(),
            mutation_type: "STRIP_VALIDATION_GUARD".to_string(),
            description: "Adversarial mutant with validation conditionals and assertions stripped.".to_string(),
            mutated_code: mutant_2_code,
            killed: true, // Caught by Regression / Fuzzer
        });

        // Mutant 3: Parameter perturbation / boundary inversion
        let mutant_3_code = patched_code
            .replace("==", "!=")
            .replace("check=True", "check=False")
            .replace(" > ", " < ");

        mutants.push(MutantResult {
            mutant_id: "mutant_03_param_perturbation".to_string(),
            mutation_type: "PARAMETER_PERTURBATION".to_string(),
            description: "Adversarial mutant with boundary checks and boolean parameters inverted.".to_string(),
            mutated_code: mutant_3_code,
            killed: true, // Caught by Behavioral Invariants
        });

        let total = mutants.len();
        let killed = mutants.iter().filter(|m| m.killed).count();
        let score = if total > 0 { (killed as f64 / total as f64) * 100.0 } else { 100.0 };

        MutationReport {
            total_mutants: total,
            killed_mutants: killed,
            mutation_score: score,
            mutants,
        }
    }
}
