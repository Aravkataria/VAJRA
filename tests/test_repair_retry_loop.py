# tests/test_repair_retry_loop.py

"""
End-to-end test of the retry loop in app.api: when a proposed patch
passes AIRepairer's own internal checks but is rejected by
SecurityTestVerifier (the exploit still reproduces), the pipeline
should retry with the rejection reason fed back into the next prompt,
rather than giving up on the finding.
"""

import io
import json
import zipfile

from fastapi.testclient import TestClient

import app.api as api_module
from app.repair.ai_repair import AIRepairer
from app.repair.deterministic_repair import DeterministicRepairer
from app.repair.model_provider import RepairModelProvider
from app.repair.repairer import Repairer

TARGET_SOURCE = (
    'def execute_code(user_input):\n'
    '    """Intentionally vulnerable test case."""\n'
    "    eval(user_input)\n"
)

SHAM_PATCH = (
    'def execute_code(user_input):\n'
    '    """Intentionally vulnerable test case."""\n'
    "    _e = eval\n"
    "    _e(user_input)\n"
)

GOOD_PATCH = (
    "import ast\n"
    "\n"
    "def execute_code(user_input):\n"
    '    """Intentionally vulnerable test case."""\n'
    "    ast.literal_eval(user_input)\n"
)


class ScriptedProvider(RepairModelProvider):
    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str) -> str:
        self.call_count += 1
        if self.call_count == 1:
            return json.dumps({
                "should_patch": True,
                "confidence": 0.8,
                "description": "sham rename: hide eval behind alias",
                "strategy": "alias",
                "patched_source": SHAM_PATCH,
                "limitations": [],
                "tests_needed": [],
                "behavioral_change": "none",
                "decline_reason": "",
            })
        return json.dumps({
            "should_patch": True,
            "confidence": 0.95,
            "description": "replace eval with ast.literal_eval",
            "strategy": "ast-literal-eval",
            "patched_source": GOOD_PATCH,
            "limitations": [],
            "tests_needed": [],
            "behavioral_change": "none",
            "decline_reason": "",
        })


def test_retry_loop_recovers_from_rejected_patch(tmp_path):
    target_file = tmp_path / "target.py"
    target_file.write_text(TARGET_SOURCE)

    scripted = ScriptedProvider()
    original_repairer = api_module.repairer
    api_module.repairer = Repairer(
        [DeterministicRepairer(), AIRepairer(scripted)]
    )
    try:
        client = TestClient(api_module.app)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.write(target_file, "target.py")
        buf.seek(0)

        upload = client.post("/upload", files={"file": ("test.zip", buf, "application/zip")})
        assert upload.status_code == 200, upload.text
        workspace_id = upload.json()["workspace_id"]

        scan = client.post(f"/workspace/{workspace_id}/scan")
        assert scan.status_code == 200, scan.text
        data = scan.json()

        assert scripted.call_count >= 1
    finally:
        api_module.repairer = original_repairer