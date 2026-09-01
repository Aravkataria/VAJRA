# app/decision/risk_prioritizer.py

"""
Section 6.5: Risk-Based Prioritization & Blast Radius Engine.

Assigns multi-factor risk scores to discovered vulnerabilities using:
1. Severity Weight (Critical=10, High=7.5, Medium=5, Low=2.5)
2. Exploitability (PoC gadget availability)
3. Dependency Reachability (Is the vulnerable symbol imported in active entrypoints?)
4. Git Change Recency (Has this file been modified in recent commits?)
5. Cyclomatic Complexity (Higher complexity = higher regression probability)

Enables VAJRA to schedule expensive deep-path reasoning and verification on the
highest-impact security risks first.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from app.analysis.finding import Finding


@dataclass
class PrioritizedFinding:
    finding: Finding
    composite_risk_score: float  # 0.0 to 100.0
    risk_tier: str               # CRITICAL, HIGH, MEDIUM, LOW
    reachability_multiplier: float
    blast_radius: str            # ISOLATED, SERVICE, SYSTEM_WIDE
    factors: Dict[str, float]


class RiskPrioritizer:
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 1.0,
    }

    @classmethod
    def calculate_risk(
        cls,
        finding: Finding,
        is_reachable: bool = True,
        recent_commit_frequency: int = 1,
        cyclomatic_complexity: int = 5,
        has_dynamic_poc: bool = True,
    ) -> PrioritizedFinding:
        # 1. Base Severity (35% weight)
        sev_key = (finding.severity or "HIGH").upper()
        sev_score = cls.SEVERITY_WEIGHTS.get(sev_key, 7.5) * 10.0 # 0 - 100

        # 2. Exploitability / PoC (25% weight)
        exploit_score = 95.0 if has_dynamic_poc else 50.0

        # 3. Reachability (20% weight)
        reach_multiplier = 1.0 if is_reachable else 0.4
        reach_score = 100.0 if is_reachable else 40.0

        # 4. Git Recency (10% weight)
        recency_score = min(recent_commit_frequency * 20.0, 100.0)

        # 5. Complexity (10% weight)
        complexity_score = min(cyclomatic_complexity * 10.0, 100.0)

        composite = (
            (sev_score * 0.35)
            + (exploit_score * 0.25)
            + (reach_score * 0.20)
            + (recency_score * 0.10)
            + (complexity_score * 0.10)
        )

        if composite >= 85.0:
            risk_tier = "CRITICAL"
            blast_radius = "SYSTEM_WIDE"
        elif composite >= 65.0:
            risk_tier = "HIGH"
            blast_radius = "SERVICE"
        elif composite >= 40.0:
            risk_tier = "MEDIUM"
            blast_radius = "ISOLATED"
        else:
            risk_tier = "LOW"
            blast_radius = "ISOLATED"

        return PrioritizedFinding(
            finding=finding,
            composite_risk_score=round(composite, 2),
            risk_tier=risk_tier,
            reachability_multiplier=reach_multiplier,
            blast_radius=blast_radius,
            factors={
                "severity_score": sev_score,
                "exploit_score": exploit_score,
                "reachability_score": reach_score,
                "recency_score": recency_score,
                "complexity_score": complexity_score,
            },
        )

    @classmethod
    def prioritize_queue(
        cls,
        findings: List[Finding],
        reachability_map: Optional[Dict[str, bool]] = None,
    ) -> List[PrioritizedFinding]:
        """Ranks a collection of findings by composite risk in descending order."""
        reachability_map = reachability_map or {}
        prioritized = []

        for f in findings:
            pkg_name = f.file.split("/")[0] if "/" in f.file else f.file
            is_reachable = reachability_map.get(pkg_name, True)
            pf = cls.calculate_risk(f, is_reachable=is_reachable)
            prioritized.append(pf)

        prioritized.sort(key=lambda x: x.composite_risk_score, reverse=True)
        return prioritized
