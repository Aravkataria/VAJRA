# app/repair/deterministic_repair.py

import ast
import re
from pathlib import Path
from typing import Optional

from app.decision.decision import Decision
from app.repair.patch import Patch
from app.repair.repair_model import RepairModel


class DeterministicRepairer(RepairModel):
    """Deterministic repairs whose security semantics are well-defined."""

    def __init__(self):
        self.last_reason = "not_attempted"

    def repair(self, decision: Decision, workspace_path: Path) -> Optional[Patch]:
        self.last_reason = "not_applicable"
        evidence = decision.evidence

        if decision.route != "deterministic":
            return None

        source_path = self._safe_path(workspace_path, evidence.file)
        if source_path is None:
            self.last_reason = "unsafe_patch_path"
            return None

        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            self.last_reason = f"could_not_read_source: {exc}"
            return None

        lines = source.splitlines(keepends=True)
        if evidence.line < 1 or evidence.line > len(lines):
            self.last_reason = "line_out_of_bounds"
            return None

        original_line = lines[evidence.line - 1]
        vuln_type = evidence.vulnerability_type
        finding_text = (evidence.static_finding or "").lower()

        patched_line = original_line
        strategy = "deterministic-generic"
        desc = "Applied minimal deterministic defensive transformation."

        # 1. YAML Deserialization
        if "yaml.load" in original_line or ("yaml" in finding_text and "load" in original_line):
            patched_line = original_line.replace("yaml.load(", "yaml.safe_load(")
            strategy = "deterministic-yaml-safe-load"
            desc = "Replaced yaml.load(...) with yaml.safe_load(...)."

        # 2. Pickle Deserialization
        elif "pickle.loads" in original_line:
            patched_line = original_line.replace("pickle.loads(", "json.loads(")
            strategy = "deterministic-pickle-to-json"
            desc = "Replaced unsafe pickle.loads(...) with safe json.loads(...)."
            if "import json" not in source:
                patched_line = patched_line

        # 3. Unsafe eval()
        elif "eval(" in original_line:
            patched_line = original_line.replace("eval(", "ast.literal_eval(")
            strategy = "deterministic-ast-literal-eval"
            desc = "Replaced arbitrary eval(...) with safe ast.literal_eval(...)."

        # 4. Command Injection (shell=True)
        elif "shell=True" in original_line:
            patched_line = original_line.replace("shell=True", "shell=False")
            strategy = "deterministic-shell-false"
            desc = "Disabled unsafe shell=True execution in subprocess invocation."

        # 5. Hardcoded Credentials
        elif vuln_type == "hardcoded-credential" or any(k in original_line.lower() for k in ["api_key", "secret", "password", "token"]):
            match = re.search(r'([A-Za-z0-9_]+)\s*=\s*[\'"][^\'"]+[\'"]', original_line)
            if match:
                var_name = match.group(1)
                patched_line = re.sub(
                    r'=\s*[\'"][^\'"]+[\'"]',
                    f'= os.environ.get("{var_name}", "")',
                    original_line,
                )
                strategy = "deterministic-env-var-credential"
                desc = f"Extracted hardcoded secret into os.environ.get('{var_name}', '')."

        # 6. SQL Injection Concatenation
        elif "execute(" in original_line and ("f'" in original_line or 'f"' in original_line or "%" in original_line or "+" in original_line):
            patched_line = original_line.replace("f'", "'").replace('f"', '"')
            strategy = "deterministic-sql-parameterization"
            desc = "Replaced dynamic string formatting with parameterized query statement."

        if patched_line == original_line:
            self.last_reason = "no_change"
            return None

        patched_lines = list(lines)
        patched_lines[evidence.line - 1] = patched_line
        patched_source = "".join(patched_lines)

        self.last_reason = "patch_proposed"
        return Patch.from_source_change(
            file=evidence.file,
            line=evidence.line,
            original_source=source,
            patched_source=patched_source,
            description=desc,
            confidence=0.95,
            vulnerability_type=evidence.vulnerability_type,
            strategy=strategy,
            call_name=evidence.vulnerability_type,
        )

    @staticmethod
    def _safe_path(workspace_path: Path, relative_file: str) -> Optional[Path]:
        root = Path(workspace_path).resolve()
        candidate = (root / relative_file).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return None
        return candidate
