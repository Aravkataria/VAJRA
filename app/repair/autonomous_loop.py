# app/repair/autonomous_loop.py

"""
Autonomous Self-Correcting Repair Evolution Loop.

Implements a multi-attempt feedback loop:
If Candidate Patch #1 fails any verification stage (syntax, static re-scan, regression, exploit sentinel),
the exact failure log and traceback are fed back into the Decision Engine to synthesize Candidate Patch #2.
Iterates up to MAX_ATTEMPTS before gracefully declining with a signed audit record.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any
from app.decision.decision import Decision
from app.repair.repairer import build_default_repairer, Repairer
from app.repair.patch import Patch
from app.verification.verifier import build_default_verifier, Verifier
from app.verification.result import VerificationResult


@dataclass
class RepairEvolutionAttempt:
    attempt_number: int
    strategy: str
    patch_diff: str
    verification_passed: bool
    failure_feedback: Optional[str]
    verifications: List[VerificationResult]


@dataclass
class AutonomousEvolutionResult:
    total_attempts: int
    successful: bool
    final_patch: Optional[Patch]
    history: List[RepairEvolutionAttempt]
    decline_reason: Optional[str]


class AutonomousRepairLoop:
    """Executes closed-loop iterative repair synthesis with verifier feedback."""

    MAX_ATTEMPTS = 3

    def __init__(self, repairer: Optional[Repairer] = None, verifier: Optional[Verifier] = None):
        self.repairer = repairer or build_default_repairer()
        self.verifier = verifier or build_default_verifier()

    def execute_loop(self, decision: Decision, workspace_path: str) -> AutonomousEvolutionResult:
        """Runs the iterative repair-verify-feedback cycle."""
        attempts_history: List[RepairEvolutionAttempt] = []

        current_decision = decision
        last_feedback = None

        for attempt_idx in range(1, self.MAX_ATTEMPTS + 1):
            # 1. Synthesize candidate repair
            patch = self.repairer.repair(current_decision, Path(workspace_path))

            if not patch:
                attempts_history.append(
                    RepairEvolutionAttempt(
                        attempt_number=attempt_idx,
                        strategy=current_decision.route,
                        patch_diff="",
                        verification_passed=False,
                        failure_feedback="Repairer declined candidate synthesis.",
                        verifications=[],
                    )
                )
                break

            # 2. Verify candidate repair
            final_res, stage_results = self.verifier.verify_with_stages(patch, Path(workspace_path))

            if final_res.verified:
                attempts_history.append(
                    RepairEvolutionAttempt(
                        attempt_number=attempt_idx,
                        strategy=current_decision.route,
                        patch_diff=patch.diff,
                        verification_passed=True,
                        failure_feedback=None,
                        verifications=stage_results,
                    )
                )
                return AutonomousEvolutionResult(
                    total_attempts=attempt_idx,
                    successful=True,
                    final_patch=patch,
                    history=attempts_history,
                    decline_reason=None,
                )

            # Failure occurred: extract feedback for next attempt
            failed_stage = next((v for v in stage_results if not v.verified), None)
            failure_feedback = f"Verification failed at [{failed_stage.method}]: {failed_stage.reason}" if failed_stage else "Verification checks failed."

            attempts_history.append(
                RepairEvolutionAttempt(
                    attempt_number=attempt_idx,
                    strategy=current_decision.route,
                    patch_diff=patch.diff,
                    verification_passed=False,
                    failure_feedback=failure_feedback,
                    verifications=stage_results,
                )
            )

            # Evolve decision with verifier feedback for next iteration
            last_feedback = failure_feedback
            current_decision = Decision(
                evidence=current_decision.evidence,
                route=current_decision.route,
                reason=current_decision.reason,
                deterministic_fix=current_decision.deterministic_fix,
                feedback=last_feedback,
            )

        # Graceful, structured decline if all attempts failed
        decline_msg = f"All {len(attempts_history)} repair attempts failed verification. Last feedback: {last_feedback}"
        return AutonomousEvolutionResult(
            total_attempts=len(attempts_history),
            successful=False,
            final_patch=None,
            history=attempts_history,
            decline_reason=decline_msg,
        )
