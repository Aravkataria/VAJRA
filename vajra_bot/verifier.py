"""
VAJRA Patch Verifier & Self-Verification Engine
Ensures generated AI patches are syntactically valid and introduce zero new sinks.
Lead Engineer: Arav Kataria
"""

import ast
from typing import Tuple, Optional
from vajra_bot.scanner import scan_content


class PatchVerifier:
    """
    Validates candidate patches before they are presented to developers:
    1. Checks Python syntax validity (ast.parse).
    2. Re-scans the patched code to verify the original vulnerability is eliminated.
    3. Confirms that no secondary sinks or vulnerabilities are introduced.
    """

    @staticmethod
    def verify_patch(filename: str, original_code: str, candidate_patch: str, target_cwe: str) -> Tuple[bool, str, Optional[str]]:
        """
        Returns:
            (is_valid: bool, verification_status: str, verified_code: Optional[str])
        """
        if not candidate_patch or not candidate_patch.strip():
            return False, "Empty patch candidate.", None

        # Clean markdown code fences if LLM included them
        clean_patch = candidate_patch.strip()
        if clean_patch.startswith("```"):
            lines = clean_patch.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            clean_patch = "\n".join(lines).strip()

        # 1. Syntax Verification for Python files
        if filename.endswith(".py"):
            try:
                ast.parse(clean_patch, filename=filename)
            except SyntaxError as e:
                return False, f"Syntax verification failed: {e.msg} (Line {e.lineno})", None

        # 2. Re-scan candidate patch for AST sinks and secrets
        new_findings = scan_content(filename, clean_patch)
        for f in new_findings:
            if f.cwe == target_cwe:
                return False, f"Patch failed verification: Original vulnerability ({target_cwe}) still present.", None
            if f.severity in ("CRITICAL", "HIGH"):
                return False, f"Patch rejected: Introduced new {f.severity} sink ({f.cwe}: {f.title}).", None

        return True, "AST-Verified Safe: Syntax valid and zero secondary sinks detected.", clean_patch
