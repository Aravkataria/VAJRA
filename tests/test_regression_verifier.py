# tests/test_regression_verifier.py

from pathlib import Path
import tempfile
import shutil
from app.repair.patch import Patch
from app.verification.regression_verifier import RegressionVerifier
from app.repository.manager import GITHUB_URL_PATTERN


def test_regression_verifier_skips_when_no_tests():
    verifier = RegressionVerifier(timeout=5)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-reg-ws-"))
    try:
        src = temp_ws / "main.py"
        src.write_text("def run(): pass\n")
        patch = Patch.from_source_change(
            file="main.py",
            line=1,
            original_source="def run(): pass\n",
            patched_source="def run(): return 42\n",
            description="return value",
            confidence=0.9,
            vulnerability_type="logic",
        )
        res = verifier.verify(patch, temp_ws)
        assert res.verified
        assert "skipped" in res.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_github_url_pattern_validation():
    valid = [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/Aravkataria/VAJRA-test",
    ]
    for u in valid:
        assert GITHUB_URL_PATTERN.match(u) is not None

    invalid = [
        "file:///etc/passwd",
        "http://github.com/owner/repo",
        "https://evil.com/owner/repo",
        "https://github.com/owner",
    ]
    for u in invalid:
        assert GITHUB_URL_PATTERN.match(u) is None