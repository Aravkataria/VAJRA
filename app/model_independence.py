# app/model_independence.py

"""
Guards against VAJRA's two reasoning stages -- the Security Analyst
(Model 1: confirms/assesses a finding) and the AI Repairer (Model 2:
proposes a patch) -- silently resolving to the same underlying model.

The whole point of splitting "is this finding real" from "how do I fix
it" into separate stages is that they reason independently: a model's
blind spot in triage is less likely to be *exactly* the same blind spot
it has when writing the patch, if it isn't the same model doing both
jobs. If they end up pointing at the same Ollama model -- most likely
because a shared env var like OLLAMA_MODEL was set once and both
providers fell back to it -- that independence is gone, silently, with
nothing in the API response to show it.

This can't guarantee two configured models have genuinely uncorrelated
failure modes -- that's a research question, not a config check. It
only catches the concrete, checkable case: both stages configured to
hit the literal same model name. Different named models can still
share the same underlying weights or training data in ways this can't
see; treat this as a floor, not a guarantee.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _resolve_model_name(component) -> Optional[str]:
    """Best-effort: dig a `.model` string out of an Analyst/Repairer's
    configured provider, however it's nested. Returns None for stages
    that aren't backed by a named model at all (e.g. the deterministic
    implementations, which have no `.model` anywhere in their chain)."""

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


def check_model_independence(analyst, repairer) -> None:
    """Log a clear warning if the analyst and any AI-backed repair
    model in the repairer's chain resolve to the same model name.

    Call this once at startup, right after both are built -- see
    app/api.py.
    """

    analyst_model_name = _resolve_model_name(analyst)
    if not analyst_model_name:
        return  # deterministic analyst: no model to collide with

    for repair_model in getattr(repairer, "models", []):
        repair_model_name = _resolve_model_name(repair_model)
        if repair_model_name and repair_model_name == analyst_model_name:
            logger.warning(
                "VAJRA's Security Analyst and %s are both configured to use "
                "the same model ('%s'). This defeats the point of separating "
                "triage from patch generation -- a blind spot in this model "
                "will show up in both stages instead of one catching the "
                "other's mistake. Set VAJRA_ANALYST_MODEL and/or "
                "VAJRA_REPAIR_MODEL to different models.",
                type(repair_model).__name__,
                analyst_model_name,
            )
