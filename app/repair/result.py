# app/repair/result.py

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RepairResult:
    status: str
    initial_findings: int
    patches_proposed: int
    patches_verified: int
    patches_applied: int
    findings_resolved: int
    findings_remaining: int
    new_findings: int
    attempts: List[Dict[str, Any]] = field(default_factory=list)
    applications: List[Dict[str, Any]] = field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = field(default_factory=list)
    remaining_findings: List[Dict[str, Any]] = field(default_factory=list)
    new_findings_detail: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "initial_findings": self.initial_findings,
            "patches_proposed": self.patches_proposed,
            "patches_verified": self.patches_verified,
            "patches_applied": self.patches_applied,
            "findings_resolved": self.findings_resolved,
            "findings_remaining": self.findings_remaining,
            "new_findings": self.new_findings,
            "attempts": self.attempts,
            "applications": self.applications,
            "resolved_findings": self.resolved_findings,
            "remaining_findings": self.remaining_findings,
            "new_findings_detail": self.new_findings_detail,
        }
