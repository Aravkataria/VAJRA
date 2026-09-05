# app/verification/result.py

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from app.repair.patch import Patch


@dataclass
class VerificationResult:
    patch: Patch
    verified: bool
    method: str
    reason: str
    remaining_findings: list[Any] = field(default_factory=list)
    performance_profile: Optional[Dict[str, Any]] = None

    def to_dict(self):
        return {
            "patch": self.patch.to_dict(),
            "verified": self.verified,
            "method": self.method,
            "reason": self.reason,
            "remaining_findings": self.remaining_findings,
            "performance_profile": self.performance_profile,
        }
