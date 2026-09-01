# app/evidence/evidence.py

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Evidence:
    """
    A single normalized evidence object, matching the schema from
    the VAJRA technical report (section 7): a compact record of
    everything known about one potential vulnerability, built up
    as different analysis layers contribute to it.

    Right now only `target`, `location`, `vulnerability`, and
    `static_analysis` are ever populated (by the static analyzer).
    `dynamic_analysis`, `fuzzing`, and `history` stay empty until
    those layers exist — the Decision Engine and later stages can
    already depend on this shape without changing later.
    """

    # --- target -----------------------------------------------------
    repository: str
    commit: Optional[str] = None

    # --- location -----------------------------------------------------
    file: str = "unknown"
    function: str = "unknown"
    line: int = 0

    # --- vulnerability -----------------------------------------------------
    vulnerability_type: str = "unknown"
    severity: str = "unknown"
    call_name: Optional[str] = None

    # --- static_analysis -----------------------------------------------------
    static_finding: Optional[str] = None

    # --- layers not implemented yet; kept as empty dicts so the
    # shape of the evidence object is stable from the start -----------------
    dynamic_analysis: dict = field(default_factory=dict)
    fuzzing: dict = field(default_factory=dict)
    history: dict = field(default_factory=dict)

    @classmethod
    def from_finding(cls, finding, repository: str, commit: Optional[str] = None):
        """
        Build an Evidence object from a single static-analysis Finding.
        """

        return cls(
            repository=repository,
            commit=commit,
            file=finding.file,
            function=finding.function,
            line=finding.line,
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            static_finding=finding.message,
            call_name=getattr(finding, "call_name", None),
        )

    def to_dict(self):
        """
        Convert to the nested dictionary shape used in the PDF's
        evidence example (target / location / vulnerability / ...).
        """

        return {
            "target": {
                "repository": self.repository,
                "commit": self.commit,
            },
            "location": {
                "file": self.file,
                "function": self.function,
                "line": self.line,
            },
            "vulnerability": {
                "type": self.vulnerability_type,
                "severity": self.severity,
                "call_name": self.call_name,
            },
            "static_analysis": {
                "finding": self.static_finding,
            },
            "dynamic_analysis": self.dynamic_analysis,
            "fuzzing": self.fuzzing,
            "history": self.history,
        }