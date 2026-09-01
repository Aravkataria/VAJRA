# app/repair/repair_model.py

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from app.decision.decision import Decision
from app.repair.patch import Patch


class RepairModel(ABC):
    """Interface for VAJRA repair generators.

    Implementations propose changes but never write to the workspace. A
    proposal is independently verified before it can be applied.
    Returning None is a normal outcome when the model cannot safely repair
    the finding. Implementations may expose ``last_reason`` for audit logs.
    """

    @abstractmethod
    def repair(self, decision: Decision, workspace_path: Path) -> Optional[Patch]:
        raise NotImplementedError
