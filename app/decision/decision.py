# app/decision/decision.py

from dataclasses import dataclass
from typing import Optional

from app.evidence.evidence import Evidence


@dataclass
class Decision:
    """
    The Decision Engine's output for one piece of evidence:
    where it should go next (PDF section 9 — 'Simple' vs 'Complex'),
    and, if a deterministic fix pattern is known, what it is.

    route is one of:
      - "deterministic": a known, safe, context-independent fix exists
      - "reasoning":      needs the context-aware reasoning repair model to
                           propose a context-aware patch
      - "none":           not an actionable vulnerability finding
    """

    evidence: Evidence

    route: str

    reason: str

    deterministic_fix: Optional[str] = None

    # Set on a retry: why the previous patch attempt for this same
    # finding was rejected by verification. AIRepairer includes this in
    # its prompt so a retry doesn't just regenerate the same rejected
    # fix. Always None on the first attempt.
    feedback: Optional[str] = None

    def to_dict(self):
        return {
            **self.evidence.to_dict(),
            "decision": {
                "route": self.route,
                "reason": self.reason,
                "deterministic_fix": self.deterministic_fix,
                "feedback": self.feedback,
            },
        }