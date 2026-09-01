# app/report/builder.py

"""
Assembles AttemptReport / AssuranceReport objects from the pipeline
objects app.api already has on hand during a scan. Nothing here computes
anything new about a patch's safety -- it only narrates decisions already
made by the Decision Engine, the repair models, and the Verifier, so the
report can never claim more than the pipeline actually established.
"""

import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.decision.decision import Decision
from app.repair.patch import Patch
from app.repair.patch_applier import PatchApplicationResult
from app.repair.repairer import RepairAttempt
from app.report.models import (
    OUTCOME_STRUCTURED_NON_REPAIR,
    OUTCOME_VERIFIED_REPAIR,
    AssuranceReport,
    AttemptReport,
    utc_now_iso,
)
from app.verification.result import VerificationResult


def build_attempt_report(
    *,
    decision: Decision,
    assessment: Optional[Any],
    model_attempts: List[RepairAttempt],
    patch: Optional[Patch],
    verification_stages: List[VerificationResult],
    final_verification: Optional[VerificationResult],
    application: Optional[PatchApplicationResult],
    repair_retry_count: int,
) -> AttemptReport:
    evidence = decision.evidence

    limitations: List[str] = []
    if patch is not None and patch.limitations:
        limitations.extend(patch.limitations)

    if patch is None:
        outcome = OUTCOME_STRUCTURED_NON_REPAIR
        # decision.reason carries the actual narrative (why the Decision
        # Engine routed here, e.g. "no deterministic fix is known, a
        # context-aware reasoning model is required"); a repair model's
        # own decline reason is often a terse internal code (e.g.
        # "not_applicable") that means nothing without that context, so
        # lead with the decision and append the model detail rather than
        # showing the terse code alone.
        outcome_reason = decision.reason
        if model_attempts:
            last = model_attempts[-1]
            if last.reason and last.reason != decision.reason:
                outcome_reason = f"{decision.reason} (repair model {last.model}: {last.reason})"
    elif final_verification is not None and not final_verification.verified:
        outcome = OUTCOME_STRUCTURED_NON_REPAIR
        outcome_reason = (
            f"Candidate patch rejected by verification stage "
            f"'{final_verification.method}': {final_verification.reason}"
        )
    elif application is not None and not application.applied:
        outcome = OUTCOME_STRUCTURED_NON_REPAIR
        outcome_reason = f"Verified patch could not be applied: {application.reason}"
    else:
        outcome = OUTCOME_VERIFIED_REPAIR
        outcome_reason = (
            "A candidate patch was generated, passed every configured "
            "verification stage, and was applied to the workspace."
        )

    return AttemptReport(
        attempt_id=str(uuid.uuid4()),
        generated_at=utc_now_iso(),
        file=evidence.file,
        line=evidence.line,
        function=evidence.function,
        vulnerability_type=evidence.vulnerability_type,
        severity=evidence.severity,
        finding_message=evidence.static_finding,
        assessment=assessment.to_dict() if assessment is not None else None,
        decision_route=decision.route,
        decision_reason=decision.reason,
        deterministic_fix=decision.deterministic_fix,
        repair_retry_count=repair_retry_count,
        retry_feedback_used=decision.feedback,
        model_attempts=[a.to_dict() for a in model_attempts],
        patch_diff=patch.diff if patch is not None else None,
        patch_description=patch.description if patch is not None else None,
        patch_strategy=patch.strategy if patch is not None else None,
        patch_confidence=patch.confidence if patch is not None else None,
        original_sha256=patch.original_sha256 if patch is not None else None,
        patched_sha256=patch.patched_sha256 if patch is not None else None,
        verification_stages=[s.to_dict() for s in verification_stages],
        final_verification_method=(
            final_verification.method if final_verification is not None else None
        ),
        final_verification_passed=(
            final_verification.verified if final_verification is not None else None
        ),
        final_verification_reason=(
            final_verification.reason if final_verification is not None else None
        ),
        applied=application.applied if application is not None else False,
        application_reason=application.reason if application is not None else None,
        finding_status=None,  # filled in by mark_finding_statuses() once known
        outcome=outcome,
        outcome_reason=outcome_reason,
        limitations=limitations,
    )


def mark_finding_statuses(
    attempt_reports: List[AttemptReport], resolved_keys: set, remaining_keys: set
) -> None:
    """
    Set each report's finding_status by matching against the post-repair
    rescan's resolved/remaining key sets (same (file, vulnerability_type,
    function, line) identity api._finding_key already uses). Mutates in
    place since AttemptReport is otherwise fully built by this point.
    """

    for report in attempt_reports:
        key = (report.file, report.vulnerability_type, report.function, report.line)
        if key in resolved_keys:
            report.finding_status = "resolved"
        elif key in remaining_keys:
            report.finding_status = "remaining"
        else:
            # Not present in either set: most often a "none" route (the
            # finding was never treated as actionable) or a stale line
            # number after an earlier patch shifted this file.
            report.finding_status = "unknown"


def build_assurance_report(
    *,
    workspace_id: str,
    attempt_reports: List[AttemptReport],
    initial_findings_count: int,
    final_findings_count: int,
    tool_versions: Dict[str, str],
) -> AssuranceReport:
    verified_repairs = sum(1 for a in attempt_reports if a.outcome == OUTCOME_VERIFIED_REPAIR)
    non_repairs = sum(1 for a in attempt_reports if a.outcome == OUTCOME_STRUCTURED_NON_REPAIR)

    summary = {
        "initial_findings": initial_findings_count,
        "final_findings": final_findings_count,
        "attempts": len(attempt_reports),
        "verified_repairs": verified_repairs,
        "structured_non_repairs": non_repairs,
    }

    return AssuranceReport(
        workspace_id=workspace_id,
        generated_at=utc_now_iso(),
        tool_versions=tool_versions,
        summary=summary,
        attempts=attempt_reports,
    )
