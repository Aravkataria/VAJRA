# app/repair/patch.py

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import difflib
import hashlib
import os


@dataclass
class Patch:
    """
    A proposed source-code change.

    The canonical representation is the complete original source and
    complete patched source for one file.  This supports multi-line edits
    while keeping the old single-line fields for compatibility/reporting.

    A Patch is only a proposal.  It must be independently verified before
    PatchApplier writes it to the real workspace.
    """

    file: str
    line: int
    original_line: str
    patched_line: str
    description: str
    confidence: float
    diff: Optional[str] = None
    original_source: Optional[str] = None
    patched_source: Optional[str] = None
    vulnerability_type: Optional[str] = None
    strategy: Optional[str] = None
    limitations: list[str] | None = None
    call_name: Optional[str] = None

    @property
    def original_sha256(self) -> Optional[str]:
        if self.original_source is None:
            return None
        return hashlib.sha256(self.original_source.encode("utf-8")).hexdigest()

    @property
    def patched_sha256(self) -> Optional[str]:
        if self.patched_source is None:
            return None
        return hashlib.sha256(self.patched_source.encode("utf-8")).hexdigest()

    @property
    def is_full_source_patch(self) -> bool:
        return self.original_source is not None and self.patched_source is not None

    @classmethod
    def from_source_change(
        cls,
        *,
        file: str,
        line: int,
        original_source: str,
        patched_source: str,
        description: str,
        confidence: float,
        vulnerability_type: Optional[str] = None,
        strategy: Optional[str] = None,
        limitations: Optional[list[str]] = None,
        call_name: Optional[str] = None,
    ) -> "Patch":
        """Create a Patch from complete before/after source text."""
        if original_source == patched_source:
            raise ValueError("Patch produces no source-code change.")

        original_lines = original_source.splitlines(keepends=True)
        patched_lines = patched_source.splitlines(keepends=True)

        diff = "".join(
            difflib.unified_diff(
                original_lines,
                patched_lines,
                fromfile=f"a/{file}",
                tofile=f"b/{file}",
                lineterm="\n",
            )
        )

        old_line = ""
        new_line = ""
        if 1 <= line <= len(original_source.splitlines()):
            old_line = original_source.splitlines()[line - 1]
        if 1 <= line <= len(patched_source.splitlines()):
            new_line = patched_source.splitlines()[line - 1]

        return cls(
            file=file,
            line=line,
            original_line=old_line,
            patched_line=new_line,
            description=description,
            confidence=float(confidence),
            diff=diff,
            original_source=original_source,
            patched_source=patched_source,
            vulnerability_type=vulnerability_type,
            strategy=strategy,
            limitations=limitations or [],
            call_name=call_name,
        )

    def apply_to_source(self, source: str) -> str:
        """Apply this patch to an exact source snapshot in memory."""
        if self.original_source is not None:
            if source != self.original_source:
                raise ValueError(
                    "Patch source snapshot does not match the current file."
                )
            return self.patched_source or ""

        # Legacy compatibility for old single-line Patch objects.
        lines = source.splitlines(keepends=True)
        if self.line < 1 or self.line > len(lines):
            raise ValueError("Patch line is out of range.")
        current = lines[self.line - 1].rstrip("\r\n")
        if current != self.original_line:
            raise ValueError("Current source does not match original_line.")
        newline = "\r\n" if lines[self.line - 1].endswith("\r\n") else "\n"
        lines[self.line - 1] = self.patched_line + newline
        return "".join(lines)

    def to_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "original_line": self.original_line,
            "patched_line": self.patched_line,
            "description": self.description,
            "confidence": self.confidence,
            "diff": self.diff,
            "vulnerability_type": self.vulnerability_type,
            "strategy": self.strategy,
            "limitations": self.limitations or [],
            "call_name": self.call_name,
            "original_sha256": self.original_sha256,
            "patched_sha256": self.patched_sha256,
            "changed": self.original_source != self.patched_source
            if self.is_full_source_patch
            else self.original_line != self.patched_line,
        }
