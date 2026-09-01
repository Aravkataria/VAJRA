# app/analysis/test_provider.py

from app.analysis.model_provider import ModelProvider


class TestProvider(ModelProvider):
    """
    Fake model provider used to test the AIAnalyst pipeline
    without calling a real AI model.
    """

    def generate(self, prompt: str) -> str:
        return """
{
  "confirmed": true,
  "confidence": 0.95,
  "vulnerability_type": "command-injection-risk",
  "severity": "high",
  "root_cause": "A command is executed through a shell-interpreted context.",
  "impact": "Untrusted input may result in unintended operating-system command execution.",
  "recommended_action": "Avoid shell interpretation and use explicit command arguments.",
  "evidence_summary": [
    "Static analysis identified command-injection-risk."
  ],
  "limitations": [
    "The test provider does not perform real model reasoning."
  ]
}
""".strip()