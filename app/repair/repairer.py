# app/repair/repairer.py

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from app.decision.decision import Decision
from app.repair.deterministic_repair import DeterministicRepairer
from app.repair.patch import Patch
from app.repair.repair_model import RepairModel


@dataclass
class RepairAttempt:
    model: str
    status: str
    reason: str
    patch: Optional[Patch] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "model": self.model,
            "status": self.status,
            "reason": self.reason,
            "patch": self.patch.to_dict() if self.patch else None,
            "details": self.details,
        }


class Repairer:
    """Orchestrate deterministic and reasoning repair models with traceability."""

    def __init__(self, models: List[RepairModel] | None = None):
        self.models = models if models is not None else [DeterministicRepairer()]
        self.last_attempts: list[RepairAttempt] = []

    def repair(self, decision: Decision, workspace_path: Path) -> Optional[Patch]:
        patch, _ = self.repair_with_trace(decision, workspace_path)
        return patch

    def repair_with_trace(
        self,
        decision: Decision,
        workspace_path: Path,
    ) -> tuple[Optional[Patch], list[RepairAttempt]]:
        attempts: list[RepairAttempt] = []

        for model in self.models:
            model_name = type(model).__name__
            try:
                patch = model.repair(decision, workspace_path)
            except Exception as exc:
                attempts.append(RepairAttempt(model_name, "error", str(exc)))
                continue

            details: dict[str, Any] = {}
            provider_metadata = getattr(model, "last_provider_metadata", None)
            if provider_metadata:
                details["provider"] = provider_metadata
            response_excerpt = getattr(model, "last_response_excerpt", None)
            if response_excerpt and os.environ.get("VAJRA_REPAIR_DEBUG", "").lower() in {"1", "true", "yes", "on"}:
                details["response_excerpt"] = response_excerpt
            model_data = getattr(model, "last_data", None)
            if isinstance(model_data, dict):
                # Do not echo a complete model-proposed source file into the
                # normal API trace. Keep the decision metadata and the patch
                # itself is represented separately when it passes validation.
                safe_keys = (
                    "should_patch", "confidence", "description", "strategy",
                    "limitations", "tests_needed", "behavioral_change",
                    "decline_reason",
                )
                details["model_response"] = {
                    key: model_data[key]
                    for key in safe_keys
                    if key in model_data
                }

            if patch is not None:
                attempts.append(
                    RepairAttempt(
                        model_name,
                        "patch_proposed",
                        getattr(model, "last_reason", "patch_proposed"),
                        patch,
                        details,
                    )
                )
                self.last_attempts = attempts
                return patch, attempts

            attempts.append(
                RepairAttempt(
                    model_name,
                    "declined_or_not_applicable",
                    getattr(model, "last_reason", "no_patch"),
                    None,
                    details,
                )
            )

        self.last_attempts = attempts
        return None, attempts

    def repair_all(self, decisions: List[Decision], workspace_path: Path) -> List[Patch]:
        patches = []
        for decision in decisions:
            patch = self.repair(decision, workspace_path)
            if patch is not None:
                patches.append(patch)
        return patches


def build_default_repairer() -> Repairer:
    mode = os.environ.get("VAJRA_REPAIR_MODE", "deterministic").lower()

    if mode == "ollama":
        from app.repair.ai_repair import AIRepairer
        from app.repair.ollama_repair_provider import OllamaRepairProvider

        return Repairer([
            DeterministicRepairer(),
            AIRepairer(OllamaRepairProvider()),
        ])

    if mode in ("ai", "reasoning"):
        from app.repair.ai_repair import AIRepairer
        from app.repair.ollama_repair_provider import OllamaRepairProvider
        return Repairer([AIRepairer(OllamaRepairProvider())])

    return Repairer([DeterministicRepairer()])
