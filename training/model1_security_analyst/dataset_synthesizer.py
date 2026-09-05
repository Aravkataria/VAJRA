# training/model1_security_analyst/dataset_synthesizer.py

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from training.model1_security_analyst.schema import DatasetSampleCategory, TrainingSample


class MultilingualDatasetSynthesizer:
    """
    Synthesizes and exports high-quality training pairs across all 8 security categories.
    Focuses on multilingual representations, independent discovery, and hard negatives.
    """

    def generate_seed_dataset(self) -> List[TrainingSample]:
        samples: List[TrainingSample] = []

        # 1. rule_and_ai_positive: Classic SQL injection (Python)
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-001-RULE-AI-SQLI",
                category=DatasetSampleCategory.RULE_AND_AI_POSITIVE,
                language="python",
                code_files={
                    "app/routes/search.py": (
                        "from flask import request\n"
                        "import sqlite3\n"
                        "@app.route('/search')\n"
                        "def search():\n"
                        "    query = request.args.get('q', '')\n"
                        "    conn = sqlite3.connect('app.db')\n"
                        "    cursor = conn.cursor()\n"
                        "    cursor.execute(f'SELECT * FROM products WHERE name LIKE \\'%{query}%\\'')\n"
                        "    return cursor.fetchall()\n"
                    )
                },
                security_ir_summary={"nodes": 2, "flows": 1, "sinks": ["sqlite3.cursor.execute"]},
                security_context={"frameworks": ["flask"], "database": ["sqlite"]},
                rule_findings=[{
                    "vulnerability_type": "sql_injection",
                    "file": "app/routes/search.py",
                    "line": 8,
                    "call_name": "execute",
                    "severity": "CRITICAL",
                }],
                expected_findings=[{
                    "finding_id": "FIND-001",
                    "category": "sql_injection",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                    "file": "app/routes/search.py",
                    "start_line": 8,
                    "end_line": 8,
                    "source": "request.args.get('q')",
                    "sink": "cursor.execute",
                    "evidence": ["Direct f-string concatenation of HTTP query parameter into SQL statement."],
                    "reasoning": "Untrusted user parameter 'q' is directly interpolated into a raw SQL query string without parameterization.",
                    "impact": "Attackers can bypass query logic, extract confidential database records, or modify table entries.",
                    "repair_required": True,
                    "review_status": "confirmed",
                    "discovery_path": "dual_confirmed",
                }],
                ground_truth_vulnerable=True,
                explanation="Standard SQL injection detected by both AST rules and AI analyst.",
            )
        )

        # 2. ai_independent_positive: Broken Object Level Authorization (IDOR) in TypeScript/Express
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-002-AI-IDOR-TS",
                category=DatasetSampleCategory.AI_INDEPENDENT_POSITIVE,
                language="typescript",
                code_files={
                    "src/controllers/userController.ts": (
                        "import { Request, Response } from 'express';\n"
                        "import { getUserByIdFromDb } from '../services/db';\n"
                        "export async function getUserProfile(req: Request, res: Response) {\n"
                        "    const userId = req.params.id;\n"
                        "    const user = await getUserByIdFromDb(userId);\n"
                        "    if (!user) return res.status(404).json({ error: 'Not found' });\n"
                        "    return res.json({ profile: user.privateProfile });\n"
                        "}\n"
                    )
                },
                security_ir_summary={"nodes": 3, "flows": 1, "boundaries": 0},
                security_context={"frameworks": ["express"], "auth": ["session"]},
                rule_findings=[],  # ZERO RULES FIRED
                expected_findings=[{
                    "finding_id": "FIND-002",
                    "category": "broken_object_level_authorization",
                    "cwe": "CWE-639",
                    "severity": "HIGH",
                    "confidence": 0.94,
                    "file": "src/controllers/userController.ts",
                    "start_line": 4,
                    "end_line": 7,
                    "source": "req.params.id",
                    "sink": "getUserByIdFromDb",
                    "evidence": ["Endpoint returns private user profile based on client ID without verifying req.user.id == userId."],
                    "reasoning": "The controller accepts an arbitrary user ID from the URL parameter and queries the database for private records without verifying if the authenticated session owns that user ID.",
                    "impact": "Any authenticated or unauthenticated client can enumerate IDs to access sensitive private profile data of any user.",
                    "repair_required": True,
                    "review_status": "confirmed",
                    "discovery_path": "ai_only",
                }],
                ground_truth_vulnerable=True,
                explanation="Independent discovery: No static rule triggers on standard ORM calls, but AI recognizes missing ownership authorization guard.",
            )
        )

        # 3. hard_negative_safe: Parameterized Query resembling SQLi (Java)
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-003-SAFE-PARAM-JAVA",
                category=DatasetSampleCategory.HARD_NEGATIVE_SAFE,
                language="java",
                code_files={
                    "src/main/java/com/app/UserDao.java": (
                        "package com.app;\n"
                        "import java.sql.*;\n"
                        "public class UserDao {\n"
                        "    public User findUser(Connection conn, String username) throws SQLException {\n"
                        "        String sql = \"SELECT * FROM users WHERE username = ?\";\n"
                        "        try (PreparedStatement stmt = conn.prepareStatement(sql)) {\n"
                        "            stmt.setString(1, username);\n"
                        "            ResultSet rs = stmt.executeQuery();\n"
                        "            return parseUser(rs);\n"
                        "        }\n"
                        "    }\n"
                        "}\n"
                    )
                },
                security_ir_summary={"nodes": 2, "controls": ["PreparedStatement.setString"]},
                security_context={"frameworks": ["jdbc"]},
                rule_findings=[],
                expected_findings=[],
                ground_truth_vulnerable=False,
                explanation="Safe code: uses PreparedStatement with parameterized placeholder '?' preventing SQL injection.",
            )
        )

        # 4. deterministic_false_positive: Integer cast makes command safe (Python)
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-004-FP-INT-CAST",
                category=DatasetSampleCategory.DETERMINISTIC_FALSE_POSITIVE,
                language="python",
                code_files={
                    "app/utils/worker.py": (
                        "import os, sys\n"
                        "from flask import request\n"
                        "@app.route('/restart_worker')\n"
                        "def restart_worker():\n"
                        "    raw_pid = request.args.get('pid', '1')\n"
                        "    clean_pid = int(raw_pid)  # Strict integer coercion\n"
                        "    os.system(f'kill -HUP {clean_pid}')\n"
                        "    return {'status': 'restarted'}\n"
                    )
                },
                security_ir_summary={"nodes": 3, "sanitizers": ["int(raw_pid)"]},
                security_context={"frameworks": ["flask"]},
                rule_findings=[{
                    "vulnerability_type": "command_injection",
                    "file": "app/utils/worker.py",
                    "line": 7,
                    "call_name": "os.system",
                    "severity": "CRITICAL",
                }],
                expected_findings=[{
                    "finding_id": "FIND-004",
                    "category": "command_injection",
                    "cwe": "CWE-78",
                    "severity": "CRITICAL",
                    "confidence": 0.15,
                    "file": "app/utils/worker.py",
                    "start_line": 7,
                    "end_line": 7,
                    "evidence": ["Variable clean_pid is constrained to a base-10 integer via int() before string formatting."],
                    "reasoning": "Although os.system is invoked, the input is strictly coerced to an integer on line 6, raising ValueError on shell metacharacters.",
                    "impact": "None. Input cannot carry shell command injection payloads.",
                    "repair_required": False,
                    "review_status": "rejected",
                    "discovery_path": "rule_candidate_ai_rejected",
                }],
                ground_truth_vulnerable=False,
                explanation="Deterministic false positive rejected by AI analyst due to strict integer type coercion guard.",
            )
        )

        # 5. multi_file_taint: Controller -> Service -> Repository cross-file taint (Go)
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-005-MULTIFILE-TAINT-GO",
                category=DatasetSampleCategory.MULTI_FILE_TAINT,
                language="go",
                code_files={
                    "controllers/admin.go": (
                        "package controllers\n"
                        "import (\n"
                        "    \"net/http\"\n"
                        "    \"app/services\"\n"
                        ")\n"
                        "func HandleExport(w http.ResponseWriter, r *http.Request) {\n"
                        "    filename := r.URL.Query().Get(\"file\")\n"
                        "    services.ExportReport(filename)\n"
                        "}\n"
                    ),
                    "services/exporter.go": (
                        "package services\n"
                        "import (\n"
                        "    \"os/exec\"\n"
                        ")\n"
                        "func ExportReport(target string) {\n"
                        "    cmd := exec.Command(\"sh\", \"-c\", \"tar -czf \"+target+\" /var/reports\")\n"
                        "    cmd.Run()\n"
                        "}\n"
                    )
                },
                security_ir_summary={"nodes": 4, "flows": 1, "is_cross_file": True},
                security_context={"frameworks": ["net/http"]},
                rule_findings=[],  # Single file scanners miss the untrusted origin
                expected_findings=[{
                    "finding_id": "FIND-005",
                    "category": "command_injection",
                    "cwe": "CWE-78",
                    "severity": "CRITICAL",
                    "confidence": 0.95,
                    "file": "services/exporter.go",
                    "start_line": 7,
                    "end_line": 8,
                    "source": "r.URL.Query().Get('file') in controllers/admin.go",
                    "sink": "exec.Command('sh', '-c', ...)",
                    "data_flow": ["controllers/admin.go:7", "services/exporter.go:6", "services/exporter.go:7"],
                    "evidence": ["Unsanitized URL query parameter in admin controller propagated to shell command invocation in exporter service."],
                    "reasoning": "HTTP input travels across package boundary from controllers to services without validation before being passed to sh -c.",
                    "impact": "Remote command execution under the execution privileges of the Go server process.",
                    "repair_required": True,
                    "review_status": "confirmed",
                    "discovery_path": "ai_only",
                }],
                ground_truth_vulnerable=True,
                explanation="Cross-file taint flow reasoning linking HTTP controller ingress to service layer shell command execution.",
            )
        )

        # 6. cross_language_equivalents: Path traversal in Rust
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-006-CROSS-LANG-RUST",
                category=DatasetSampleCategory.CROSS_LANGUAGE_EQUIVALENTS,
                language="rust",
                code_files={
                    "src/handlers/download.rs": (
                        "use actix_web::{web, HttpResponse, Responder};\n"
                        "use std::fs;\n"
                        "pub async fn download_file(info: web::Path<String>) -> impl Responder {\n"
                        "    let filename = info.into_inner();\n"
                        "    let path = format!(\"/var/data/uploads/{}\", filename);\n"
                        "    match fs::read_to_string(&path) {\n"
                        "        Ok(contents) => HttpResponse::Ok().body(contents),\n"
                        "        Err(_) => HttpResponse::NotFound().finish(),\n"
                        "    }\n"
                        "}\n"
                    )
                },
                security_ir_summary={"nodes": 3, "sinks": ["fs::read_to_string"]},
                security_context={"frameworks": ["actix_web"]},
                rule_findings=[],
                expected_findings=[{
                    "finding_id": "FIND-006",
                    "category": "path_traversal",
                    "cwe": "CWE-22",
                    "severity": "HIGH",
                    "confidence": 0.93,
                    "file": "src/handlers/download.rs",
                    "start_line": 5,
                    "end_line": 6,
                    "source": "info.into_inner()",
                    "sink": "fs::read_to_string(&path)",
                    "evidence": ["Raw URL path segment appended directly to base directory without canonicalization or component checking."],
                    "reasoning": "The path segment can contain '../' sequence to escape the /var/data/uploads/ directory.",
                    "impact": "Arbitrary file read of host filesystem accessible to the application.",
                    "repair_required": True,
                    "review_status": "confirmed",
                    "discovery_path": "ai_only",
                }],
                ground_truth_vulnerable=True,
                explanation="Language-agnostic path traversal concept applied to Rust actix-web.",
            )
        )

        # 7. complex_context_positive: Missing Rate Limiting on Login (Python/FastAPI)
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-007-COMPLEX-RATE-LIMIT",
                category=DatasetSampleCategory.COMPLEX_CONTEXT_POSITIVE,
                language="python",
                code_files={
                    "app/api/auth.py": (
                        "from fastapi import APIRouter, HTTPException, Depends\n"
                        "from pydantic import BaseModel\n"
                        "router = APIRouter()\n"
                        "class LoginRequest(BaseModel):\n"
                        "    username: str\n"
                        "    password: str\n"
                        "@router.post('/login')\n"
                        "async def login(req: LoginRequest):\n"
                        "    user = authenticate(req.username, req.password)\n"
                        "    if not user:\n"
                        "        raise HTTPException(status_code=401, detail='Invalid credentials')\n"
                        "    return {'token': create_jwt(user)}\n"
                    )
                },
                security_ir_summary={"nodes": 3, "endpoints": 1, "controls": []},
                security_context={"frameworks": ["fastapi"], "auth": ["jwt"]},
                rule_findings=[],
                expected_findings=[{
                    "finding_id": "FIND-007",
                    "category": "missing_rate_limiting",
                    "cwe": "CWE-770",
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "file": "app/api/auth.py",
                    "start_line": 8,
                    "end_line": 13,
                    "source": "POST /login",
                    "sink": "authenticate",
                    "evidence": ["Authentication endpoint lacks throttle decorator, IP rate limiting, or captcha protection."],
                    "reasoning": "High-sensitivity authentication route accepts unlimited repeated requests without rate limits.",
                    "impact": "Susceptible to high-speed password spraying, credential stuffing, and brute force attacks.",
                    "repair_required": True,
                    "review_status": "confirmed",
                    "discovery_path": "ai_only",
                }],
                ground_truth_vulnerable=True,
                explanation="Complex context positive: Missing architectural abuse controls on sensitive endpoint.",
            )
        )

        # 8. uncertain_security_case: Ambiguous Custom Encryption Wrapper (C#)
        samples.append(
            TrainingSample(
                sample_id="SAMPLE-008-UNCERTAIN-CRYPTO-CS",
                category=DatasetSampleCategory.UNCERTAIN_SECURITY_CASE,
                language="csharp",
                code_files={
                    "Services/SecurityService.cs": (
                        "namespace App.Services {\n"
                        "    public class SecurityService {\n"
                        "        public byte[] ProcessData(byte[] input) {\n"
                        "            // Delegates to uninspectable external hardware/native module\n"
                        "            return NativeCryptoBridge.TransformBuffer(input);\n"
                        "        }\n"
                        "    }\n"
                        "}\n"
                    )
                },
                security_ir_summary={"nodes": 1, "sinks": ["NativeCryptoBridge.TransformBuffer"]},
                security_context={"frameworks": ["dotnet"]},
                rule_findings=[],
                expected_findings=[{
                    "finding_id": "FIND-008",
                    "category": "weak_cryptography",
                    "cwe": "CWE-327",
                    "severity": "MEDIUM",
                    "confidence": 0.40,
                    "file": "Services/SecurityService.cs",
                    "start_line": 5,
                    "end_line": 5,
                    "evidence": ["Calls unverified external bridge NativeCryptoBridge.TransformBuffer."],
                    "reasoning": "Cannot verify cipher mode, key strength, or algorithm without native bridge definition.",
                    "impact": "Potential cryptographic weakness if legacy primitive is wrapped by external module.",
                    "repair_required": False,
                    "review_status": "uncertain",
                    "discovery_path": "ai_only",
                }],
                ground_truth_vulnerable=False,
                explanation="Uncertain case correctly labeled with review_status=uncertain instead of hallucinating certainty.",
            )
        )

        return samples

    def export_jsonl(self, samples: List[TrainingSample], output_path: Path) -> int:
        """Export dataset to JSONL file in instruction tuning format."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            for sample in samples:
                chat_obj = sample.to_chat_format()
                f.write(json.dumps(chat_obj) + "\n")
        return len(samples)
