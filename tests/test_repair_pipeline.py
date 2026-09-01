# tests/test_repair_pipeline.py

import tempfile
import unittest
from pathlib import Path

from app.analysis.deterministic_analyst import DeterministicAnalyst
from app.analysis.python_static import analyze_source
from app.decision.engine import decide
from app.evidence.evidence import Evidence
from app.repair.ai_repair import AIRepairer
from app.repair.model_provider import RepairModelProvider
from app.repair.repairer import Repairer
from app.verification.verifier import Verifier


class FakeProvider(RepairModelProvider):
    def generate(self, prompt: str) -> str:
        return '''{"should_patch":true,"confidence":0.95,"description":"Replace unrestricted evaluation with constrained literal parsing.","strategy":"ast-literal-eval","patched_source":"import ast\\n\\ndef execute_code(user_input):\\n    ast.literal_eval(user_input)\\n","limitations":["This changes behavior from arbitrary code execution to literal parsing."],"tests_needed":["Reject non-literal input without executing code."],"behavioral_change":"expected","decline_reason":""}'''


class RefusalProvider(RepairModelProvider):
    def generate(self, prompt: str) -> str:
        return '''{"should_patch":false,"confidence":0.95,"description":"Insufficient semantics.","strategy":"decline","limitations":["Unknown intended behavior."],"decline_reason":"unknown intended behavior"}'''


class RepairPipelineTests(unittest.TestCase):
    source = """import ast\n\ndef execute_code(user_input):\n    eval(user_input)\n"""

    def _decision(self, source):
        finding = analyze_source("vulnerable.py", source)[0]
        evidence = Evidence.from_finding(finding, repository="test")
        assessment = DeterministicAnalyst().analyze(evidence)
        return decide(evidence, assessment)

    def test_ai_patch_is_verified(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "vulnerable.py").write_text(self.source, encoding="utf-8")
            decision = self._decision(self.source)
            patch = AIRepairer(FakeProvider()).repair(decision, root)
            self.assertIsNotNone(patch)
            result = Verifier().verify(patch, root)
            self.assertTrue(result.verified, result.reason)

    def test_refusal_is_traced(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "vulnerable.py").write_text(self.source, encoding="utf-8")
            decision = self._decision(self.source)
            repairer = Repairer([AIRepairer(RefusalProvider())])
            patch, attempts = repairer.repair_with_trace(decision, root)
            self.assertIsNone(patch)
            self.assertEqual(len(attempts), 1)
            self.assertTrue(attempts[0].reason.startswith("model_declined:"))


if __name__ == "__main__":
    unittest.main()