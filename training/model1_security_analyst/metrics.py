# training/model1_security_analyst/metrics.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EvaluationConfusionMatrix:
    dual_confirmed: int = 0         # Vuln: Rule=Yes, AI=Yes
    rule_only: int = 0              # Vuln: Rule=Yes, AI=No
    ai_only: int = 0                # Vuln: Rule=No,  AI=Yes (Independent Discovery)
    missed_by_both: int = 0         # Vuln: Rule=No,  AI=No
    rule_false_positive: int = 0    # Safe: Rule=Yes, AI=No (AI successfully rejected)
    ai_false_positive: int = 0      # Safe: Rule=No,  AI=Yes (AI incorrectly flagged)
    both_false_positive: int = 0    # Safe: Rule=Yes, AI=Yes

    @property
    def total_ground_truth_vulnerabilities(self) -> int:
        return self.dual_confirmed + self.rule_only + self.ai_only + self.missed_by_both

    @property
    def total_ground_truth_safe(self) -> int:
        return self.rule_false_positive + self.ai_false_positive + self.both_false_positive

    @property
    def independent_discovery_rate(self) -> float:
        """
        Independent Discovery Rate =
        genuine AI-only vulnerabilities / all benchmark vulnerabilities missed by rules
        """
        missed_by_rules = self.ai_only + self.missed_by_both
        if missed_by_rules == 0:
            return 1.0 if self.ai_only > 0 else 0.0
        return self.ai_only / missed_by_rules

    @property
    def ai_precision(self) -> float:
        tp = self.dual_confirmed + self.ai_only
        fp = self.ai_false_positive + self.both_false_positive
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @property
    def ai_recall(self) -> float:
        tp = self.dual_confirmed + self.ai_only
        fn = self.rule_only + self.missed_by_both
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @property
    def ai_f1(self) -> float:
        p = self.ai_precision
        r = self.ai_recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

    def to_report_dict(self) -> Dict[str, Any]:
        return {
            "matrix": {
                "Dual_Confirmed": self.dual_confirmed,
                "Rule_Only": self.rule_only,
                "AI_Only_Independent_Discovery": self.ai_only,
                "Missed_By_Both": self.missed_by_both,
                "Rule_False_Positive_Correctly_Rejected": self.rule_false_positive,
                "AI_False_Positive": self.ai_false_positive,
            },
            "metrics": {
                "Independent_Discovery_Rate": round(self.independent_discovery_rate, 4),
                "AI_Precision": round(self.ai_precision, 4),
                "AI_Recall": round(self.ai_recall, 4),
                "AI_F1_Score": round(self.ai_f1, 4),
                "Total_Ground_Truth_Vulnerabilities": self.total_ground_truth_vulnerabilities,
            },
        }
