# app/analysis/adapters/base.py

"""
Base Analysis Adapter Interface.

Allows VAJRA to aggregate evidence interchangeably from Native AST Visitors,
Semgrep rules, Bandit, or Dynamic Runtime Tracers into a unified Evidence schema.
"""

from abc import ABC, abstractmethod
from typing import List
from app.analysis.finding import Finding


class BaseAnalysisAdapter(ABC):
    """Abstract interface for all static, dynamic, and external security analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def analyze(self, workspace_path: str) -> List[Finding]:
        """Runs the analyzer over the workspace and returns structured Findings."""
        pass
