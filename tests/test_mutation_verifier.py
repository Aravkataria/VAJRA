# tests/test_mutation_verifier.py

from pathlib import Path
import tempfile
import shutil
from app.repair.patch import Patch
from app.verification.mutation_verifier import PatchMutationVerifier


def test_mutation_verifier_eval_patch():
    verifier = PatchMutationVerifier(max_mutants=2)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-mutation-ws-"))
    try:
        src = temp_ws / "eval_code.py"
        src.write_text("def run(cmd):\n    eval(cmd)\n")

        patch = Patch.from_source_change(
            file="eval_code.py",
            line=2,
            original_source="def run(cmd):\n    eval(cmd)\n",
            patched_source="import ast\ndef run(cmd):\n    ast.literal_eval(cmd)\n",
            description="use literal_eval",
            confidence=0.9,
            vulnerability_type="unsafe-eval",
        )

        res = verifier.verify(patch, temp_ws)
        assert res.verified
        assert "patch-mutation-testing" in res.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)