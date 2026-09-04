# app/verification/verifier.py

from pathlib import Path
from typing import List

from app.repair.patch import Patch
from app.verification.fuzzing_verifier import FuzzingVerifier
from app.verification.mutation_verifier import PatchMutationVerifier
from app.verification.regression_verifier import RegressionVerifier
from app.verification.result import VerificationResult
from app.verification.security_test_verifier import SecurityTestVerifier
from app.verification.smt_verifier import SMTVerifier
from app.verification.static_rescan_verifier import StaticRescanVerifier
from app.verification.syntax_verifier import SyntaxVerifier
from app.verification.verification_model import VerificationModel


class Verifier:
    """Runs independent verification stages in order for VAJRA."""

    def __init__(self, models: List[VerificationModel] | None = None):
        self.models = (
            models
            if models is not None
            else [
                SyntaxVerifier(),
                StaticRescanVerifier(),
                SecurityTestVerifier(),
                RegressionVerifier(),
                FuzzingVerifier(),
                PatchMutationVerifier(),
                SMTVerifier(),
            ]
        )

    def verify_with_stages(
        self, patch: Patch, workspace_path: Path
    ) -> tuple[VerificationResult, List[VerificationResult]]:
        stage_results: List[VerificationResult] = []
        for model in self.models:
            result = model.verify(patch, workspace_path)
            stage_results.append(result)
            if not result.verified:
                return result, stage_results

        final = VerificationResult(
            patch,
            True,
            "verification-pipeline",
            "All configured verification stages passed successfully.",
        )
        stage_results.append(final)
        return final, stage_results

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        final, _ = self.verify_with_stages(patch, workspace_path)
        return final

    def verify_all(self, patches: List[Patch], workspace_path: Path) -> List[VerificationResult]:
        return [self.verify(patch, workspace_path) for patch in patches]


def build_default_verifier() -> Verifier:
    return Verifier()