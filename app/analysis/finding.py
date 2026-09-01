# app/analysis/finding.py

from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """
    A deterministic security finding produced by an analysis layer.

    Finding represents what an analyzer observed.
    It does not decide whether the finding is exploitable,
    how confident we are, or how it should be repaired.

    Those responsibilities belong to later VAJRA stages.
    """

    file: str
    line: int
    vulnerability_type: str
    severity: str
    message: str
    function: str = "module"
    call_name: Optional[str] = None

    def to_dict(self):
        """
        Convert the finding into a plain dictionary suitable
        for API responses and later evidence processing.
        """

        return {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "message": self.message,
            "call_name": self.call_name,
        }