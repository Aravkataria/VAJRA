# app/verification/syntax_verifier.py

from pathlib import Path

from app.repair.patch import Patch
from app.repository.language import detect_language
from app.verification.result import VerificationResult
from app.verification.syntax.checkers import CHECKERS
from app.verification.verification_model import VerificationModel


class SyntaxVerifier(VerificationModel):
    """Check the complete candidate source without modifying the workspace.

    Dispatches to a per-language checker (app.verification.syntax.checkers)
    based on the patched file's extension. Python -- VAJRA's only real
    analysis target today -- always has a checker. Other languages are
    checked when a matching tool (node, bash, PyYAML, ...) is available
    in this environment; otherwise this stage defers rather than
    guessing, the same "no evidence either way, don't block" pattern
    SecurityTestVerifier uses when it has no exploit-PoC template.
    """

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        root = Path(workspace_path).resolve()
        source_path = (root / patch.file).resolve()
        try:
            source_path.relative_to(root)
        except ValueError:
            return VerificationResult(
                patch, False, "syntax", "Patch path escapes workspace."
            )

        try:
            source = source_path.read_text(encoding="utf-8")
            patched_source = patch.apply_to_source(source)
        except (OSError, ValueError) as exc:
            return VerificationResult(
                patch,
                False,
                "syntax",
                f"Could not construct candidate source: {exc}",
            )

        language = detect_language(patch.file)
        checker = CHECKERS.get(language)
        if checker is None:
            return VerificationResult(
                patch,
                True,
                "syntax:skipped",
                f"No syntax checker available for '{language}'; deferring to "
                "other verification stages.",
            )

        result = checker(patched_source, patch.file)
        if result is None:
            return VerificationResult(
                patch,
                True,
                "syntax:skipped",
                f"The tool needed to check {language} syntax isn't installed "
                "in this environment; deferring to other verification stages.",
            )

        ok, message = result
        return VerificationResult(patch, ok, "syntax", message)
