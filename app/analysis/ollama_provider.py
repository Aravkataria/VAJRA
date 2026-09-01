# app/analysis/ollama_provider.py

import json
import os

import requests

from app.analysis.model_provider import ModelProvider

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT_SECONDS = 120


class OllamaProvider(ModelProvider):
    """
    ModelProvider backed by a local Ollama server.

    This is VAJRA's first real (non-fake) model provider. It talks
    to Ollama's /api/generate endpoint and asks for JSON-formatted
    output so the AIAnalyst's response parser can rely on getting
    valid JSON back most of the time.

    Ollama must be running locally with the requested model already
    pulled, e.g.:

        ollama pull llama3.1
        ollama serve

    Configuration can come from constructor args or environment
    variables (OLLAMA_URL, OLLAMA_MODEL), so the provider can be
    swapped or pointed elsewhere without code changes.
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        # VAJRA_ANALYST_MODEL takes priority over the shared OLLAMA_MODEL
        # fallback on purpose: OLLAMA_MODEL also feeds OllamaRepairProvider
        # (see repair/ollama_repair_provider.py), so relying on it alone
        # would let the analyst and repairer silently end up on the same
        # model -- exactly the correlated-blind-spot problem the two-stage
        # design exists to avoid. See app/model_independence.py.
        self.model = (
            model
            or os.environ.get("VAJRA_ANALYST_MODEL")
            or os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
        )
        self.base_url = (
            base_url or os.environ.get("OLLAMA_URL", DEFAULT_OLLAMA_URL)
        ).rstrip("/")
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to the local Ollama model and return its
        raw text response.

        Raises RuntimeError if Ollama can't be reached or returns
        an error, so callers get a clear signal instead of a
        confusing downstream JSON-parse failure.
        """

        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # Ask Ollama to constrain output to valid JSON. Supported
            # by JSON-capable models (llama3.1, qwen2.5, mistral, etc).
            "format": "json",
            "options": {
                # Low temperature: VAJRA wants consistent, evidence-
                # grounded assessments, not creative variation.
                "temperature": 0.1,
            },
        }

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self.base_url}. "
                f"Is 'ollama serve' running?"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                f"Ollama request timed out after {self.timeout}s "
                f"(model={self.model})."
            ) from exc
        except requests.exceptions.HTTPError as exc:
            raise RuntimeError(
                f"Ollama returned an error for model '{self.model}': {exc}"
            ) from exc

        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Ollama response was not valid JSON at the transport level."
            ) from exc

        text = data.get("response")

        if not text:
            raise RuntimeError(
                "Ollama response did not contain a 'response' field."
            )

        return text
