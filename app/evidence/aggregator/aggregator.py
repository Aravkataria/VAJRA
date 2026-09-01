# app/evidence/aggregator.py

from typing import Optional

from app.evidence.evidence import Evidence

# Higher number = higher priority. Anything unrecognized sorts last.
SEVERITY_RANK = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


def build_evidence(findings, repository: str, commit: Optional[str] = None):
    """
    Convert a list of static-analysis Finding objects into a list
    of normalized Evidence objects, sorted with the most severe,
    most actionable findings first.

    This is deliberately simple for now — one finding maps to one
    evidence object. Once dynamic analysis and fuzzing exist,
    evidence for the same location will be merged here instead of
    staying one-to-one with static findings.
    """

    evidence_list = [
        Evidence.from_finding(finding, repository=repository, commit=commit)
        for finding in findings
    ]

    evidence_list.sort(
        key=lambda e: (
            -SEVERITY_RANK.get(e.severity, 0),
            e.file,
            e.line,
        )
    )

    return evidence_list


def evidence_to_dicts(evidence_list):
    """
    Convenience helper for API responses: convert a list of
    Evidence objects into plain dictionaries.
    """

    return [evidence.to_dict() for evidence in evidence_list]