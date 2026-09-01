# tests/test_storage_memory.py

from pathlib import Path
import tempfile
import shutil
from app.storage.db import Database
from app.report.models import AttemptReport, utc_now_iso


def test_sqlite_failure_memory_recording():
    td = Path(tempfile.mkdtemp(prefix="vajra-test-db-"))
    try:
        db = Database(db_path=td / "test.db")
        att = AttemptReport(
            attempt_id="att-1",
            generated_at=utc_now_iso(),
            file="vuln.py",
            line=10,
            function="run",
            vulnerability_type="unsafe-eval",
            severity="HIGH",
            finding_message="eval used",
            assessment=None,
            decision_route="reasoning",
            decision_reason="test",
            deterministic_fix=None,
            repair_retry_count=1,
            retry_feedback_used=None,
            model_attempts=[],
            patch_diff=None,
            patch_description=None,
            patch_strategy=None,
            patch_confidence=None,
            original_sha256=None,
            patched_sha256=None,
            verification_stages=[],
            final_verification_method="security-test",
            final_verification_passed=False,
            final_verification_reason="PoC triggered",
            applied=False,
            application_reason=None,
            finding_status=None,
            outcome="structured_non_repair",
            outcome_reason="PoC triggered failure",
        )
        db.record_attempt(att, "ws-1")
        mem = db.get_failure_memory("unsafe-eval", "vuln.py")
        assert len(mem) == 1
        assert mem[0]["attempt_id"] == "att-1"
        assert mem[0]["final_method"] == "security-test"
    finally:
        shutil.rmtree(td, ignore_errors=True)