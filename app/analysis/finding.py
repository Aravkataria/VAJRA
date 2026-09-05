# app/analysis/finding.py

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DiscoveryPath(str, Enum):
    RULE_ONLY = "rule_only"
    AI_ONLY = "ai_only"
    DUAL_CONFIRMED = "dual_confirmed"
    RULE_CANDIDATE_AI_REJECTED = "rule_candidate_ai_rejected"
    RULE_CANDIDATE_AI_UNCERTAIN = "rule_candidate_ai_uncertain"


class ReviewStatus(str, Enum):
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"
    REJECTED = "rejected"


@dataclass
class FindingLocation:
    start_line: int
    end_line: int
    function: str = "module"
    enclosing_class: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_line": self.start_line,
            "end_line": self.end_line,
            "function": self.function,
            "enclosing_class": self.enclosing_class,
        }


@dataclass
class UnifiedFinding:
    """
    VAJRA Unified Security Finding Schema.
    
    Standardized, verifiable finding representation produced by either
    deterministic rule engines, Model 1 independent reasoning, or dual-path fusion.
    """
    finding_id: str
    category: str
    cwe: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    file: str
    location: FindingLocation
    source: Optional[str] = None
    sink: Optional[str] = None
    data_flow: List[str] = field(default_factory=list)
    security_boundary: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    reasoning: str = ""
    impact: str = ""
    repair_required: bool = True
    review_status: ReviewStatus = ReviewStatus.CONFIRMED
    discovery_path: DiscoveryPath = DiscoveryPath.DUAL_CONFIRMED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "cwe": self.cwe,
            "severity": self.severity.upper(),
            "confidence": round(self.confidence, 4),
            "file": self.file,
            "location": self.location.to_dict(),
            "source": self.source,
            "sink": self.sink,
            "data_flow": self.data_flow,
            "security_boundary": self.security_boundary,
            "evidence": self.evidence,
            "reasoning": self.reasoning,
            "impact": self.impact,
            "repair_required": self.repair_required,
            "review_status": self.review_status.value if isinstance(self.review_status, ReviewStatus) else str(self.review_status),
            "discovery_path": self.discovery_path.value if isinstance(self.discovery_path, DiscoveryPath) else str(self.discovery_path),
        }


@dataclass
class Finding:
    """
    A legacy deterministic security finding produced by an analysis layer.
    Retained for 100% backward compatibility with existing scanner layers.
    """

    file: str
    line: int
    vulnerability_type: str
    severity: str
    message: str
    function: str = "module"
    call_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding into a plain dictionary."""
        return {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "message": self.message,
            "call_name": self.call_name,
        }

    def to_unified(self, finding_id: str, cwe: str = "CWE-Unknown") -> UnifiedFinding:
        """Upgrade a legacy Finding into a UnifiedFinding."""
        return UnifiedFinding(
            finding_id=finding_id,
            category=self.vulnerability_type,
            cwe=cwe,
            severity=self.severity,
            confidence=0.85,
            file=self.file,
            location=FindingLocation(start_line=self.line, end_line=self.line, function=self.function),
            sink=self.call_name or self.vulnerability_type,
            evidence=[self.message],
            reasoning=f"Deterministic rule matched pattern '{self.call_name or self.vulnerability_type}'",
            impact=f"Potential {self.vulnerability_type} at {self.file}:{self.line}",
            repair_required=True,
            review_status=ReviewStatus.CONFIRMED,
            discovery_path=DiscoveryPath.RULE_ONLY,
        )