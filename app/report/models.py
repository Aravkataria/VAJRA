# app/report/models.py

"""
Data model for the Repair Assurance Report for VAJRA.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

UNIMPLEMENTED_VERIFICATION_STAGES = [
    "dynamic-sanitizer-instrumentation",
    "binary-coverage-comparison",
]

OUTCOME_VERIFIED_REPAIR = "verified_repair"
OUTCOME_STRUCTURED_NON_REPAIR = "structured_non_repair"


@dataclass
class VerificationStageReport:
    method: str
    verified: bool
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"method": self.method, "verified": self.verified, "reason": self.reason}


@dataclass
class RepairModelAttemptReport:
    model: str
    status: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"model": self.model, "status": self.status, "reason": self.reason}


@dataclass
class AttemptReport:
    attempt_id: str
    generated_at: str

    file: str
    line: int
    function: str
    vulnerability_type: str
    severity: str
    finding_message: Optional[str]

    assessment: Optional[Dict[str, Any]]

    decision_route: str
    decision_reason: str
    deterministic_fix: Optional[str]
    repair_retry_count: int
    retry_feedback_used: Optional[str]

    model_attempts: List[Dict[str, Any]]

    patch_diff: Optional[str]
    patch_description: Optional[str]
    patch_strategy: Optional[str]
    patch_confidence: Optional[float]
    original_sha256: Optional[str]
    patched_sha256: Optional[str]

    verification_stages: List[Dict[str, Any]]
    final_verification_method: Optional[str]
    final_verification_passed: Optional[bool]
    final_verification_reason: Optional[str]

    applied: bool
    application_reason: Optional[str]

    finding_status: Optional[str]
    outcome: str
    outcome_reason: str

    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "generated_at": self.generated_at,
            "finding": {
                "file": self.file,
                "line": self.line,
                "function": self.function,
                "vulnerability_type": self.vulnerability_type,
                "severity": self.severity,
                "message": self.finding_message,
            },
            "assessment": self.assessment,
            "decision": {
                "route": self.decision_route,
                "reason": self.decision_reason,
                "deterministic_fix": self.deterministic_fix,
                "repair_retry_count": self.repair_retry_count,
                "retry_feedback_used": self.retry_feedback_used,
            },
            "model_attempts": self.model_attempts,
            "patch": (
                {
                    "diff": self.patch_diff,
                    "description": self.patch_description,
                    "strategy": self.patch_strategy,
                    "confidence": self.patch_confidence,
                    "original_sha256": self.original_sha256,
                    "patched_sha256": self.patched_sha256,
                }
                if self.patch_diff is not None
                else None
            ),
            "verification": {
                "stages": self.verification_stages,
                "final_method": self.final_verification_method,
                "final_passed": self.final_verification_passed,
                "final_reason": self.final_verification_reason,
            },
            "application": {
                "applied": self.applied,
                "reason": self.application_reason,
            },
            "finding_status": self.finding_status,
            "outcome": self.outcome,
            "outcome_reason": self.outcome_reason,
            "limitations": self.limitations,
        }


@dataclass
class AssuranceReport:
    workspace_id: str
    generated_at: str
    tool_versions: Dict[str, str]
    summary: Dict[str, Any]
    attempts: List[AttemptReport]
    unperformed_checks: List[str] = field(
        default_factory=lambda: list(UNIMPLEMENTED_VERIFICATION_STAGES)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "generated_at": self.generated_at,
            "tool_versions": self.tool_versions,
            "summary": self.summary,
            "attempts": [a.to_dict() for a in self.attempts],
            "unperformed_checks": self.unperformed_checks,
            "position": (
                "An accepted repair means the identified vulnerability was mitigated "
                "under the verification conditions recorded above, and no tested "
                "regression or newly introduced issue was found within the scope of "
                "those checks. It does not mean the software is guaranteed secure."
            ),
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")