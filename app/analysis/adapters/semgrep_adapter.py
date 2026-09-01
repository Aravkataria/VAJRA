# app/analysis/adapters/semgrep_adapter.py

"""
Semgrep Analysis Adapter.

Wraps Semgrep CLI output when available on PATH, converting Semgrep JSON findings
directly into unified VAJRA Finding objects. If Semgrep is not installed, gracefully
returns empty findings without crashing.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List
from app.analysis.adapters.base import BaseAnalysisAdapter
from app.analysis.finding import Finding


class SemgrepAdapter(BaseAnalysisAdapter):
    @property
    def name(self) -> str:
        return "Semgrep Static Analyzer"

    def analyze(self, workspace_path: str) -> List[Finding]:
        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin:
            return []

        try:
            cmd = [
                semgrep_bin,
                "--config=auto",
                "--json",
                "--quiet",
                str(workspace_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode not in [0, 1] or not res.stdout:
                return []

            data = json.loads(res.stdout)
            findings: List[Finding] = []

            for item in data.get("results", []):
                rule_id = item.get("check_id", "semgrep.vulnerability")
                path_str = item.get("path", "")
                try:
                    rel_path = str(Path(path_str).relative_to(workspace_path))
                except Exception:
                    rel_path = path_str

                line = item.get("start", {}).get("line", 1)
                msg = item.get("extra", {}).get("message", "Semgrep security finding")

                # Map check_id to VAJRA vulnerability types
                v_type = "command_injection" if "command" in rule_id or "eval" in rule_id else (
                    "sql_injection" if "sql" in rule_id else (
                        "insecure_deserialization" if "pickle" in rule_id or "yaml" in rule_id else "general_weakness"
                    )
                )

                findings.append(
                    Finding(
                        file_path=rel_path,
                        line_number=line,
                        vulnerability_type=v_type,
                        message=f"[Semgrep] {msg}",
                        evidence={"source": "semgrep", "rule_id": rule_id},
                    )
                )

            return findings
        except Exception:
            return []
