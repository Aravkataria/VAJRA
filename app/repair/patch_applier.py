# app/repair/patch_applier.py

from dataclasses import dataclass
from pathlib import Path
import os
import tempfile

from app.repair.patch import Patch


@dataclass
class PatchApplicationResult:
    applied: bool
    file: str
    line: int
    reason: str

    def to_dict(self):
        return {
            "applied": self.applied,
            "file": self.file,
            "line": self.line,
            "reason": self.reason,
        }


class PatchApplier:
    """Writes only an already-verified patch to a contained workspace path."""

    def _safe_path(self, workspace_path: Path, relative_file: str) -> Path:
        root = Path(workspace_path).resolve()
        candidate = (root / relative_file).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Patch path escapes workspace: {relative_file}") from exc
        return candidate

    def apply(self, patch: Patch, workspace_path: Path) -> PatchApplicationResult:
        try:
            source_path = self._safe_path(workspace_path, patch.file)
        except ValueError as exc:
            return PatchApplicationResult(False, patch.file, patch.line, str(exc))

        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            return PatchApplicationResult(False, patch.file, patch.line, f"Could not read target file: {exc}")

        try:
            new_source = patch.apply_to_source(source)
        except ValueError as exc:
            return PatchApplicationResult(False, patch.file, patch.line, f"Patch rejected: {exc}")

        if new_source == source:
            return PatchApplicationResult(False, patch.file, patch.line, "Patch produces no source-code change.")

        # Atomic replacement: write the candidate beside the target and
        # replace the target only after the complete write succeeds.
        temp_name = None
        try:
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{source_path.name}.",
                suffix=".vajra.tmp",
                dir=str(source_path.parent),
                text=True,
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp:
                tmp.write(new_source)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(temp_name, source_path)
            temp_name = None
        except OSError as exc:
            return PatchApplicationResult(False, patch.file, patch.line, f"Could not atomically write patched file: {exc}")
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

        return PatchApplicationResult(True, patch.file, patch.line, "Patch applied successfully.")
