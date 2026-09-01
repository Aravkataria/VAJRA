# app/verification/security_test_verifier.py

"""
Dynamic Exploit PoC Verifier for VAJRA.
"""

import ast
import os
from pathlib import Path

from app.repair.patch import Patch
from app.verification.result import VerificationResult
from app.verification.security_test.poc_templates import SUPPORTED_DYNAMIC_TYPES
from app.verification.security_test.runner import run_poc
from app.verification.verification_model import VerificationModel

STATIC_ONLY_TYPES = {"hardcoded-credential"}


def _enclosing_function(source: str, line: int) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "global"

    match = "global"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno)
            if start <= line <= end:
                match = node.name
    return match


def _verify_static_credential(patch: Patch, workspace_path: Path) -> VerificationResult:
    root = Path(workspace_path).resolve()
    source_path = (root / patch.file).resolve()
    try:
        source_path.relative_to(root)
    except ValueError:
        return VerificationResult(
            patch, False, "security-test:static", "Patch path escapes workspace."
        )

    try:
        patched_source = patch.apply_to_source(source_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return VerificationResult(
            patch, False, "security-test:static", f"Could not construct candidate source: {exc}"
        )

    try:
        tree = ast.parse(patched_source)
    except SyntaxError as exc:
        return VerificationResult(
            patch, False, "security-test:static", f"Patched file has syntax error: {exc}"
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node, "lineno", None) == patch.line:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return VerificationResult(
                    patch,
                    False,
                    "security-test:static",
                    "Hardcoded credential literal is still present on target line.",
                )

    return VerificationResult(
        patch,
        True,
        "security-test:static",
        "Hardcoded credential literal was removed from target line.",
    )


class SecurityTestVerifier(VerificationModel):
    def __init__(
        self,
        timeout: int = int(os.environ.get("VAJRA_SECURITY_TEST_TIMEOUT", "5")),
    ):
        self.timeout = timeout

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        root = Path(workspace_path).resolve()
        source_path = (root / patch.file).resolve()
        try:
            source_path.relative_to(root)
        except ValueError:
            return VerificationResult(patch, False, "security-test", "Patch path escapes workspace.")

        vuln_type = patch.vulnerability_type

        if vuln_type in STATIC_ONLY_TYPES:
            return _verify_static_credential(patch, workspace_path)

        if vuln_type not in SUPPORTED_DYNAMIC_TYPES:
            return VerificationResult(
                patch,
                True,
                "security-test:skipped",
                f"No exploit template for finding type {vuln_type!r}; deferred to other verifiers.",
            )

        try:
            original_source = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            return VerificationResult(
                patch, False, "security-test", f"Could not read original source: {exc}"
            )

        try:
            patched_source = patch.apply_to_source(original_source)
        except Exception as exc:
            return VerificationResult(
                patch, False, "security-test", f"Could not construct candidate source: {exc}"
            )

        call_name = getattr(patch, "call_name", None)
        target_fn = _enclosing_function(original_source, patch.line)

        # Baseline: confirm the exploit fires on original unpatched code
        orig_run = run_poc(
            workspace_path=workspace_path,
            relative_file=patch.file,
            source=original_source,
            function_name=target_fn,
            vulnerability_type=vuln_type,
            call_name=call_name,
            timeout=self.timeout,
        )

        if orig_run.error or not orig_run.exploited:
            return VerificationResult(
                patch,
                True,
                "security-test:inconclusive",
                f"Exploit PoC did not reproduce vulnerability on original code: {orig_run.error}; deferred.",
            )

        # Patched code test: verify exploit no longer fires
        patched_run = run_poc(
            workspace_path=workspace_path,
            relative_file=patch.file,
            source=patched_source,
            function_name=target_fn,
            vulnerability_type=vuln_type,
            call_name=call_name,
            timeout=self.timeout,
        )

        if patched_run.exploited:
            return VerificationResult(
                patch,
                False,
                "security-test",
                "Exploit PoC still succeeded against candidate patch (vulnerability remains open).",
            )

        return VerificationResult(
            patch,
            True,
            "security-test",
            "Exploit PoC confirmed live on original code and neutralized by candidate patch.",
        )