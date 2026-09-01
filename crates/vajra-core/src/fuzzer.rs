use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzSeed {
    pub seed_id: String,
    pub category: String,
    pub payload: String,
    pub length_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCorpusReport {
    pub total_seeds: usize,
    pub categories_covered: Vec<String>,
    pub seeds: Vec<FuzzSeed>,
}

pub struct FuzzCorpusGenerator;

impl FuzzCorpusGenerator {
    /// Generates high-throughput boundary payload corpus for target sink verification
    pub fn generate_corpus(vuln_type: &str, depth: usize) -> FuzzCorpusReport {
        let mut seeds = Vec::new();

        // 1. Boundary & Buffer Overflow Seeds
        seeds.push(FuzzSeed {
            seed_id: "seed_buf_1k".to_string(),
            category: "BUFFER_OVERFLOW".to_string(),
            payload: "A".repeat(1024),
            length_bytes: 1024,
        });

        seeds.push(FuzzSeed {
            seed_id: "seed_buf_64k".to_string(),
            category: "BUFFER_OVERFLOW".to_string(),
            payload: "B".repeat(65536),
            length_bytes: 65536,
        });

        // 2. Metacharacter & Command Injection Probes
        let cmd_probes = vec![
            "; id",
            "| whoami",
            "& ping -c 1 127.0.0.1",
            "$(echo 'INJECTED')",
            "`id`",
            "${IFS}cat${IFS}/etc/passwd",
            "\n/bin/sh\n",
            "|| true #",
        ];

        for (i, p) in cmd_probes.into_iter().enumerate() {
            seeds.push(FuzzSeed {
                seed_id: format!("seed_cmd_{}", i + 1),
                category: "COMMAND_METACHARACTER".to_string(),
                payload: p.to_string(),
                length_bytes: p.len(),
            });
        }

        // 3. Null Byte & Unicode Encodings
        let unicode_probes = vec![
            "\x00",
            "\x00\x00\x00\x00",
            "\u{FFFD}\u{FFFF}",
            "\u{202E}txt.exe", // Right-to-Left Override
            "\r\n\r\nHTTP/1.1 200 OK\r\n",
            "%00",
            "%2e%2e%2f",
        ];

        for (i, p) in unicode_probes.into_iter().enumerate() {
            seeds.push(FuzzSeed {
                seed_id: format!("seed_encoding_{}", i + 1),
                category: "ENCODING_AND_NULL".to_string(),
                payload: p.to_string(),
                length_bytes: p.len(),
            });
        }

        // 4. Path Traversal Fuzz Vectors
        let path_probes = vec![
            "../../../../../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/shadow",
            "/var/log/../../../../etc/passwd%00.png",
        ];

        for (i, p) in path_probes.into_iter().enumerate() {
            seeds.push(FuzzSeed {
                seed_id: format!("seed_path_{}", i + 1),
                category: "PATH_TRAVERSAL".to_string(),
                payload: p.to_string(),
                length_bytes: p.len(),
            });
        }

        // 5. Deep Nested payloads based on requested depth
        for d in 1..=depth.min(10) {
            let nested = format!("{}{}{}", "{\"a\":".repeat(d), "1", "}".repeat(d));
            seeds.push(FuzzSeed {
                seed_id: format!("seed_nested_depth_{}", d),
                category: "NESTED_STRUCTURE".to_string(),
                payload: nested.clone(),
                length_bytes: nested.len(),
            });
        }

        let categories: Vec<String> = seeds
            .iter()
            .map(|s| s.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let total = seeds.len();

        FuzzCorpusReport {
            total_seeds: total,
            categories_covered: categories,
            seeds,
        }
    }
}
