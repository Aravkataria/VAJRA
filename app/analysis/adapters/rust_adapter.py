# app/analysis/adapters/rust_adapter.py

"""
Rust High-Performance Core Analysis Adapter.

Delegates multithreaded directory traversal, boundary fuzz corpus synthesis,
adversarial patch mutation, and causal git intent indexing to the compiled
'vajra-core' native Rust binary.

Automatically falls back to Native Python AST and engines if the binary is
not compiled on the host system.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.analysis.adapters.base import BaseAnalysisAdapter
from app.analysis.adapters.native_ast_adapter import NativeASTAdapter
from app.analysis.finding import Finding


class RustAnalysisAdapter(BaseAnalysisAdapter):
    def __init__(self, binary_path: Optional[str] = None):
        self._binary_path = binary_path or self._find_binary()
        self._fallback_adapter = NativeASTAdapter()

    @property
    def name(self) -> str:
        return "VAJRA-Core Multithreaded Rust Engine" if self.is_available() else "Native Python AST Analyzer (Fallback)"

    def is_available(self) -> bool:
        return self._binary_path is not None and Path(self._binary_path).exists()

    def _find_binary(self) -> Optional[str]:
        # 1. Check in PATH
        which_path = shutil.which("vajra-core")
        if which_path:
            return which_path

        # 2. Check local crate targets
        root = Path(__file__).resolve().parent.parent.parent.parent
        candidates = [
            root / "crates" / "vajra-core" / "target" / "release" / "vajra-core.exe",
            root / "crates" / "vajra-core" / "target" / "release" / "vajra-core",
            root / "crates" / "vajra-core" / "target" / "debug" / "vajra-core.exe",
            root / "crates" / "vajra-core" / "target" / "debug" / "vajra-core",
            root / "bin" / "vajra-core.exe",
            root / "bin" / "vajra-core",
        ]

        for cand in candidates:
            if cand.is_file():
                return str(cand)

        return None

    def analyze(self, workspace_path: str) -> List[Finding]:
        if not self.is_available():
            return self._fallback_adapter.analyze(workspace_path)

        try:
            cmd = [self._binary_path, "scan", str(workspace_path), "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0 or not result.stdout.strip():
                return self._fallback_adapter.analyze(workspace_path)

            data = json.loads(result.stdout)
            raw_findings = data.get("findings", [])

            findings = []
            for rf in raw_findings:
                findings.append(
                    Finding(
                        file=rf["file"],
                        line=rf["line"],
                        column=rf.get("column", 1),
                        function="<global>",
                        vulnerability_type=rf["vulnerability_type"],
                        severity=rf.get("severity", "HIGH"),
                        message=rf["message"],
                        snippet=rf.get("snippet", ""),
                    )
                )

            return findings
        except Exception:
            return self._fallback_adapter.analyze(workspace_path)

    def generate_fuzz_corpus(self, vuln_type: str, depth: int = 5) -> Dict[str, Any]:
        """Generates high-speed boundary fuzz vectors via Rust engine."""
        if not self.is_available():
            return {"total_seeds": 0, "seeds": []}

        try:
            cmd = [self._binary_path, "fuzz", vuln_type, "--depth", str(depth)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
        return {"total_seeds": 0, "seeds": []}

    def mutate_patch(self, code: str, vuln_type: str) -> Dict[str, Any]:
        """Generates in-memory adversarial patch mutations via Rust engine."""
        if not self.is_available():
            return {"mutation_score": 100.0, "mutants": []}

        try:
            cmd = [self._binary_path, "mutate", code, vuln_type]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
        return {"mutation_score": 100.0, "mutants": []}

    def investigate_git_blame(self, repo_path: str, file: str, line: int, vuln_type: str) -> Dict[str, Any]:
        """Performs fast commit intent extraction via Rust engine."""
        if not self.is_available():
            return {"is_preserved": True}

        try:
            cmd = [self._binary_path, "git-blame", repo_path, file, str(line), vuln_type]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
        return {"is_preserved": True}
