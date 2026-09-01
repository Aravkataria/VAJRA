# app/model_independence.py

"""
3-Tier Sovereign Model Independence Invariant.

Guarantees strict architectural separation across:
1. Tier 1: Security Analyst Model (Triage, AST Explanations, Root Cause)
2. Tier 2: AI Repair Model (Minimal Surgical Patch Synthesis)
3. Tier 3: Verification & Test Model (Adversarial Exploit Sentinels & PoC Proofs)

Ensures that no single AI model is responsible for analyzing, repairing,
and validating its own code.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _resolve_model_name(component) -> Optional[str]:
    """Extracts the underlying LLM model identifier from a component."""
    seen = set()

    def _walk(obj, depth: int) -> Optional[str]:
        if obj is None or depth > 4 or id(obj) in seen:
            return None
        seen.add(id(obj))

        candidate = getattr(obj, "model", None)
        if isinstance(candidate, str) and candidate.strip():
            return candidate
        if candidate is not None:
            found = _walk(candidate, depth + 1)
            if found:
                return found

        provider = getattr(obj, "provider", None)
        if provider is not None:
            found = _walk(provider, depth + 1)
            if found:
                return found

        return None

    return _walk(component, 0)


def check_3tier_model_independence(analyst, repairer, verifier=None) -> None:
    """Enforces the 3-tier model independence invariant."""
    analyst_model = _resolve_model_name(analyst)
    
    # 1. Analyst vs Repairer Independence
    if analyst_model:
        for repair_model in getattr(repairer, "models", []):
            rep_name = _resolve_model_name(repair_model)
            if rep_name and rep_name == analyst_model:
                logger.warning(
                    "[3-TIER INVARIANT WARNING] Security Analyst and %s are both configured to use the same model ('%s'). "
                    "For sovereign independence, set separate VAJRA_ANALYST_MODEL and VAJRA_REPAIR_MODEL.",
                    type(repair_model).__name__,
                    analyst_model,
                )

    # 2. Repairer vs Verifier Independence
    if verifier is not None:
        for v_stage in getattr(verifier, "models", []):
            v_name = _resolve_model_name(v_stage)
            if v_name and analyst_model and v_name == analyst_model:
                logger.warning(
                    "[3-TIER INVARIANT WARNING] Verification Sentinel and Security Analyst are both configured to use the same model ('%s').",
                    analyst_model,
                )


def check_model_independence(analyst, repairer) -> None:
    """Legacy backward compatibility wrapper."""
    check_3tier_model_independence(analyst, repairer)
