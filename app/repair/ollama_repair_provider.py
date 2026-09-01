# app/repair/ollama_repair_provider.py

import json
import logging
import os
from typing import Any

import requests

from app.repair.model_provider import RepairModelProvider

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:3b"
DEFAULT_TIMEOUT_SECONDS = 120


class OllamaRepairProvider(RepairModelProvider):
    """Repair-model provider backed by a local Ollama server.

    The provider is deliberately thin: it communicates with Ollama and
    returns the model's raw response. Parsing and security validation belong
    to AIRepairer.
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int | None = None,
    ):
        # VAJRA_REPAIR_MODEL / OLLAMA_REPAIR_MODEL both take priority over
        # the shared OLLAMA_MODEL fallback -- see the matching comment in
        # analysis/ollama_provider.py and app/model_independence.py.
        self.model = (
            model
            or os.environ.get("VAJRA_REPAIR_MODEL")
            or os.environ.get("OLLAMA_REPAIR_MODEL")
            or os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
        )
        self.base_url = (
            base_url or os.environ.get("OLLAMA_URL", DEFAULT_OLLAMA_URL)
        ).rstrip("/")
        self.timeout = int(
            timeout
            if timeout is not None
            else os.environ.get("VAJRA_REPAIR_TIMEOUT", DEFAULT_TIMEOUT_SECONDS)
        )
        self.temperature = float(os.environ.get("VAJRA_REPAIR_TEMPERATURE", "0.0"))
        self.num_ctx = int(os.environ.get("VAJRA_REPAIR_NUM_CTX", "8192"))
        self.num_predict = int(os.environ.get("VAJRA_REPAIR_NUM_PREDICT", "4096"))
        self.last_metadata: dict[str, Any] = {}

    @staticmethod
    def _debug_enabled() -> bool:
        return os.environ.get("VAJRA_REPAIR_DEBUG", "").lower() in {
            "1", "true", "yes", "on"
        }

    def generate(self, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }

        self.last_metadata = {
            "provider": "ollama",
            "model": self.model,
            "url": url,
            "timeout": self.timeout,
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self.base_url}. Is Ollama running?"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                f"Ollama repair request timed out after {self.timeout}s "
                f"(model={self.model})."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        if response.status_code >= 400:
            body = response.text[:1000]
            raise RuntimeError(
                f"Ollama returned HTTP {response.status_code} for model "
                f"'{self.model}': {body}"
            )

        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Ollama transport response was not valid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise RuntimeError("Ollama transport response must be a JSON object.")

        text = data.get("response")
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("Ollama response did not contain a non-empty 'response'.")

        self.last_metadata.update(
            {
                "done": data.get("done"),
                "done_reason": data.get("done_reason"),
                "total_duration_ns": data.get("total_duration"),
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
                "response_length": len(text),
            }
        )

        if self._debug_enabled():
            logger.info(
                "Ollama repair response: model=%s done_reason=%s length=%d preview=%r",
                self.model,
                data.get("done_reason"),
                len(text),
                text[:1200],
            )

        return text
