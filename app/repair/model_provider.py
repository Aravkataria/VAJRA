# app/repair/model_provider.py

from abc import ABC, abstractmethod


class RepairModelProvider(ABC):
    """
    Interface for VAJRA's AI Repair Model providers.

    Providers are responsible only for communicating with an AI model.
    They return the model's raw text response.

    The AIRepairer is responsible for constructing the prompt and
    validating/parsing the response.
    """

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """
        Generate a response from the configured repair model.
        """
        raise NotImplementedError