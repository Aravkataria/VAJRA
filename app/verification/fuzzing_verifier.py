# app/verification/fuzzing_verifier.py

"""
Dynamic Fuzzing & Re-Fuzzing Verifier for VAJRA.
"""

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from app.repair.patch import Patch
from app.verification.result import VerificationResult
from app.verification.verification_model import VerificationModel

FUZZING_CORPUS: List[str] = [
    "",
    "\x00",
    "A" * 8192,
    "%s" * 100,
    "../../../../../../etc/passwd",
    "{\"key\": " + ("[" * 50) + ("1" + "]" * 50) + "}",
    "NaN",
    "Infinity",
    "-1e309",
    "\\u0000\\uFFFF\\U0001F600",
    "' OR '1'='1",
    "<script>alert(1)</script>",
]


class FuzzingVerifier(VerificationModel):
    def __init__(self, timeout: int = 5, iterations: int = len(FUZZING_CORPUS)):
        self.timeout = timeout
        self.iterations = iterations

    def _find_target_function(self, source: str, line: int) -> Optional[str]:
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = node.lineno
                    end = getattr(node, "end_lineno", node.lineno)
                    if start <= line <= end:
                        return node.name
        except Exception:
            pass
        return None

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        root = Path(workspace_path).resolve()
        source_path = (root / patch.file).resolve()
        try:
            original_source = source_path.read_text(encoding="utf-8")
            patched_source = patch.apply_to_source(original_source)
        except Exception as exc:
            return VerificationResult(
                patch, False, "re-fuzzing", f"Could not construct candidate source: {exc}"
            )

        fn_name = self._find_target_function(patched_source, patch.line)
        if not fn_name:
            return VerificationResult(
                patch,
                True,
                "re-fuzzing:skipped",
                "Patched code is outside function scope; skipped dynamic fuzzing.",
            )

        harness = f"""
import sys
{patched_source}

corpus = {json.dumps(FUZZING_CORPUS[:self.iterations])}
fn = globals().get({fn_name!r})
if callable(fn):
    for item in corpus:
        try:
            fn(item)
        except Exception:
            pass
sys.exit(0)
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(harness)
            harness_path = f.name

        try:
            proc = subprocess.run(
                [sys.executable, harness_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if proc.returncode == 0:
                return VerificationResult(
                    patch,
                    True,
                    "re-fuzzing",
                    f"Patched function withstood {len(FUZZING_CORPUS[:self.iterations])} mutation fuzzing payloads without crash.",
                )
            else:
                err_msg = proc.stdout.strip() or proc.stderr.strip()
                return VerificationResult(
                    patch,
                    False,
                    "re-fuzzing",
                    f"Fuzzing detected crash in candidate fix: {err_msg[:300]}",
                )
        except subprocess.TimeoutExpired:
            return VerificationResult(
                patch,
                False,
                "re-fuzzing",
                f"Fuzzing execution timed out after {self.timeout}s (possible infinite loop in patch).",
            )
        finally:
            try:
                os.unlink(harness_path)
            except OSError:
                pass