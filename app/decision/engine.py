# app/decision/engine.py

from app.decision.decision import Decision


# Vulnerability types that have a known, safe, context-independent
# fix — one that doesn't require understanding what the surrounding
# code is actually trying to do. Only yaml.load -> yaml.safe_load
# qualifies today (handled separately below, since it also needs a
# text match on the finding); this dict exists so future patterns
# like it have one place to be added without new routing logic.
#
# command-injection-risk and hardcoded-credential deliberately do
# NOT belong here: "use subprocess.run() instead of os.system()" or
# "move this credential to an env var" isn't a drop-in text swap —
# it depends on what the surrounding code is actually doing. They
# route to "reasoning" below instead, where AIRepairer can look at
# the real context before proposing anything.
DETERMINISTIC_FIXES = {}


def decide(evidence, assessment):
    """
    Decide what should happen next using both the original evidence
    and the Security Analyst's assessment.

    Evidence tells us what was observed.
    Assessment tells us how strongly the finding is supported.
    """

    vuln_type = evidence.vulnerability_type
    finding_text = (evidence.static_finding or "").lower()

    # ---------------------------------------------------------
    # Parse errors are not vulnerabilities.
    # ---------------------------------------------------------

    if vuln_type == "parse-error":
        return Decision(
            evidence=evidence,
            route="none",
            reason=(
                "Not a vulnerability finding; the file could not be parsed."
            ),
        )

    # ---------------------------------------------------------
    # Model 1 confidence gate
    # ---------------------------------------------------------
    #
    # Do not generate or recommend a repair when the AI Security
    # Analyst does not consider the finding sufficiently supported.
    #
    # We use both confirmation and confidence rather than trusting
    # either value independently.
    # ---------------------------------------------------------

    if not assessment.confirmed:
        return Decision(
            evidence=evidence,
            route="none",
            reason=(
                "Security Analyst did not confirm the finding. "
                f"Confidence: {assessment.confidence:.2f}."
            ),
        )

    if assessment.confidence < 0.70:
        return Decision(
            evidence=evidence,
            route="none",
            reason=(
                "Security Analyst confidence is below the repair "
                f"threshold ({assessment.confidence:.2f} < 0.70)."
            ),
        )

    # ---------------------------------------------------------
    # Deterministic fixes
    # ---------------------------------------------------------

    if vuln_type == "unsafe-deserialization" and "yaml" in finding_text:
        return Decision(
            evidence=evidence,
            route="deterministic",
            reason=(
                "Security Analyst confirmed the finding and yaml.load "
                "has a safe, drop-in replacement."
            ),
            deterministic_fix=(
                "Replace yaml.load(...) with yaml.safe_load(...)."
            ),
        )

    if vuln_type in DETERMINISTIC_FIXES:
        return Decision(
            evidence=evidence,
            route="deterministic",
            reason=(
                "Security Analyst confirmed the finding and a known "
                "safe replacement pattern exists."
            ),
            deterministic_fix=DETERMINISTIC_FIXES[vuln_type],
        )

    # ---------------------------------------------------------
    # Complex findings → reasoning / Model 2
    # ---------------------------------------------------------

    return Decision(
        evidence=evidence,
        route="reasoning",
        reason=(
            "Security Analyst confirmed the finding, but no deterministic "
            "fix is known. A context-aware reasoning model is required "
            "to propose the repair."
        ),
    )


def decide_all(evidence_list, assessments):
    """
    Run the Decision Engine over Evidence and corresponding
    Security Assessments.

    Each Evidence object must have a corresponding Assessment
    at the same list position.
    """

    if len(evidence_list) != len(assessments):
        raise ValueError(
            "Evidence and Security Assessment counts must match."
        )

    return [
        decide(evidence, assessment)
        for evidence, assessment in zip(
            evidence_list,
            assessments,
        )
    ]