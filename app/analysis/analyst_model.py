# app/analysis/analyst_model.py

from abc import ABC, abstractmethod

from app.analysis.assessment import SecurityAssessment
from app.evidence.evidence import Evidence


class AnalystModel(ABC):
    """
    Interface for the VAJRA Security Analyst model.

    Implementations receive structured Evidence and produce
    a structured SecurityAssessment.

    Implementations may later use:

    - deterministic rules
    - local LLMs
    - remote AI APIs
    - other reasoning systems
    """

    @abstractmethod
    def analyze(self, evidence: Evidence) -> SecurityAssessment:
        """
        Analyze one evidence item and produce a security assessment.
        """

        raise NotImplementedError