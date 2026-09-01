# tests/test_fuzzing_verifier.py

"""
Tests for FuzzingVerifier.
"""

from pathlib import Path
import tempfile
import shutil

from app.repair.patch import Patch
from app.verification.fuzzing_verifier import FuzzingVerifier


def test_fuzzing_verifier_resilient_patch():
    verifier = FuzzingVerifier(timeout=5, iterations=5)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-fuzz-ws-"))
    try:
        src = temp_ws / "parser.py"
        src.write_text("def parse_data(raw):\n    return str(raw).strip()\n")

        patch = Patch.from_source_change(
            file="parser.py",
            line=2,
            original_source="def parse_data(raw):\n    return str(raw).strip()\n",
            patched_source="def parse_data(raw):\n    if raw is None:\n        return ''\n    return str(raw).strip()\n",
            description="handle null gracefully",
            confidence=0.95,
            vulnerability_type="null-pointer-deref",
        )

        res = verifier.verify(patch, temp_ws)
        assert res.verified
        assert res.method == "re-fuzzing"
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)
