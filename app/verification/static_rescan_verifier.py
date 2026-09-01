# app/verification/static_rescan_verifier.py

from pathlib import Path

from app.analysis.python_static import analyze_source
from app.repair.patch import Patch
from app.verification.result import VerificationResult
from app.verification.verification_model import VerificationModel


class StaticRescanVerifier(VerificationModel):
    """Re-run the analyzer over the complete candidate file.

    Verification is based on vulnerability counts rather than the original
    line number, because a valid multi-line patch can move code.
    """

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        root = Path(workspace_path).resolve()
        source_path = (root / patch.file).resolve()
        try:
            source_path.relative_to(root)
        except ValueError:
            return VerificationResult(
                patch, False, "static-rescan", "Patch path escapes workspace."
            )

        try:
            source = source_path.read_text(encoding="utf-8")
            patched_source = patch.apply_to_source(source)
        except (OSError, ValueError) as exc:
            return VerificationResult(
                patch, False, "static-rescan", f"Could not construct candidate source: {exc}"
            )

        original_findings = analyze_source(patch.file, source)
        candidate_findings = analyze_source(patch.file, patched_source)

        before: dict[str, int] = {}
        after: dict[str, int] = {}
        for finding in original_findings:
            before[finding.vulnerability_type] = before.get(finding.vulnerability_type, 0) + 1
        for finding in candidate_findings:
            after[finding.vulnerability_type] = after.get(finding.vulnerability_type, 0) + 1

        target = patch.vulnerability_type
        if target:
            if after.get(target, 0) >= before.get(target, 0):
                remaining = [
                    f.to_dict()
                    for f in candidate_findings
                    if f.vulnerability_type == target
                ]
                return VerificationResult(
                    patch,
                    False,
                    "static-rescan",
                    f"Static re-analysis did not reduce the original vulnerability count for {target}.",
                    remaining_findings=remaining,
                )

        # A repair must not create a new analyzer-detected vulnerability type
        # or increase an existing type count.
        increases = []
        for vuln_type, count_after in after.items():
            count_before = before.get(vuln_type, 0)
            if count_after > count_before:
                increases.append(f"{vuln_type}: {count_before} -> {count_after}")

        if increases:
            return VerificationResult(
                patch,
                False,
                "static-rescan",
                "Candidate introduced or increased security findings: " + ", ".join(increases),
                remaining_findings=[f.to_dict() for f in candidate_findings],
            )

        return VerificationResult(
            patch,
            True,
            "static-rescan",
            "Static re-analysis reduced the target vulnerability count and introduced no new/increased analyzer finding type.",
        )
