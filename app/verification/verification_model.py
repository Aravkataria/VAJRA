# app/verification/verification_model.py

from abc import ABC, abstractmethod
from pathlib import Path

from app.repair.patch import Patch
from app.verification.result import VerificationResult


class VerificationModel(ABC):
    """Independent verification stage for VAJRA.

    A verifier must inspect the candidate patch without modifying the real
    workspace.
    """

    @abstractmethod
    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        raise NotImplementedError