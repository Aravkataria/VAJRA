# app/analysis/model_provider.py

from abc import ABC, abstractmethod


class ModelProvider(ABC):
    """
    Generic interface for an AI model provider.

    The provider is responsible only for communicating with
    an underlying model.

    It does not decide how VAJRA interprets vulnerabilities.
    """

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """
        Send a prompt to the model and return its response.
        """

        raise NotImplementedError