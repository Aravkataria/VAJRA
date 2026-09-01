# app/analysis/assessment.py

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SecurityAssessment:
    """
    Structured assessment produced by VAJRA's Security Analyst.

    The analyst does not generate a patch.

    Its responsibility is to interpret the available evidence
    and determine whether the finding appears sufficiently
    supported, what the likely root cause is, and what kind
    of action should happen next.

    This object is intentionally model-independent so that the
    analyst can later be backed by an LLM without changing the
    rest of the pipeline.
    """

    confirmed: bool

    confidence: float

    vulnerability_type: str

    severity: str

    root_cause: str

    impact: str

    recommended_action: str

    evidence_summary: List[str] = field(default_factory=list)

    limitations: List[str] = field(default_factory=list)

    def to_dict(self):
        """
        Convert the assessment into a JSON-compatible dictionary.
        """

        return {
            "confirmed": self.confirmed,
            "confidence": self.confidence,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "root_cause": self.root_cause,
            "impact": self.impact,
            "recommended_action": self.recommended_action,
            "evidence_summary": self.evidence_summary,
            "limitations": self.limitations,
        }