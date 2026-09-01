# app/analysis/analyst.py

import os

from app.analysis.analyst_model import AnalystModel
from app.analysis.deterministic_analyst import DeterministicAnalyst


class SecurityAnalyst:
    """
    VAJRA Security Analyst orchestration layer.

    The SecurityAnalyst delegates vulnerability assessment
    to an AnalystModel implementation.

    The current default implementation is DeterministicAnalyst.

    Later, an AI-based analyst can be injected without changing
    the rest of the VAJRA analysis pipeline.
    """

    def __init__(self, model: AnalystModel | None = None):
        """
        Create a SecurityAnalyst.

        If no model is supplied, VAJRA uses the deterministic
        analyst implementation.
        """

        self.model = model or DeterministicAnalyst()

    def analyze(self, evidence):
        """
        Analyze one normalized Evidence object.
        """

        return self.model.analyze(evidence)

    def analyze_all(self, evidence_list):
        """
        Analyze multiple Evidence objects.
        """

        return [
            self.analyze(evidence)
            for evidence in evidence_list
        ]


def build_default_analyst() -> SecurityAnalyst:
    """
    Build the SecurityAnalyst VAJRA should use by default, chosen by
    the VAJRA_ANALYST_MODE environment variable:

      - "deterministic" (default) -> rule-based DeterministicAnalyst
      - "ollama"                  -> AI-backed AIAnalyst using a
                                      local Ollama model

    Kept out of api.py so the selection logic has one home and can
    grow (e.g. a real Anthropic/OpenAI provider) without touching
    the routes that use it.
    """

    mode = os.environ.get("VAJRA_ANALYST_MODE", "deterministic").lower()

    if mode == "ollama":
        # Imported lazily so environments without `requests` installed
        # (or without Ollama running) can still use the deterministic
        # analyst without hitting an import error.
        from app.analysis.ai_analyst import AIAnalyst
        from app.analysis.ollama_provider import OllamaProvider

        return SecurityAnalyst(model=AIAnalyst(OllamaProvider()))

    return SecurityAnalyst()