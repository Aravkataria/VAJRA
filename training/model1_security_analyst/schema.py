# training/model1_security_analyst/schema.py

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DatasetSampleCategory(str, Enum):
    RULE_AND_AI_POSITIVE = "rule_and_ai_positive"
    AI_INDEPENDENT_POSITIVE = "ai_independent_positive"
    HARD_NEGATIVE_SAFE = "hard_negative_safe"
    DETERMINISTIC_FALSE_POSITIVE = "deterministic_false_positive"
    MULTI_FILE_TAINT = "multi_file_taint"
    CROSS_LANGUAGE_EQUIVALENTS = "cross_language_equivalents"
    COMPLEX_CONTEXT_POSITIVE = "complex_context_positive"
    UNCERTAIN_SECURITY_CASE = "uncertain_security_case"


@dataclass
class TrainingSample:
    sample_id: str
    category: DatasetSampleCategory
    language: str
    code_files: Dict[str, str]  # filepath -> content
    security_ir_summary: Dict[str, Any]
    security_context: Dict[str, Any]
    rule_findings: List[Dict[str, Any]]
    expected_findings: List[Dict[str, Any]]
    ground_truth_vulnerable: bool
    explanation: str

    def to_chat_format(self, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """Convert sample into standard instruction-tuning multi-turn chat format."""
        sys_p = system_prompt or (
            "You are VAJRA Model 1: Multilingual AI Security Analyst. "
            "Analyze the provided code and Security IR to produce structured, evidence-grounded findings "
            "adhering to the VAJRA Unified Security Finding Schema. Do not generate exploit payloads."
        )

        user_content = f"""[APPLICATION AUDIT REQUEST]
Languages: {self.language}
Sample Type: {self.category.value}
Security Context: {self.security_context}
Deterministic Rule Findings: {self.rule_findings}

Source Code:
"""
        for fpath, code in self.code_files.items():
            user_content += f"\n--- File: {fpath} ---\n{code}\n"

        assistant_content = {
            "findings": self.expected_findings,
            "ground_truth_vulnerable": self.ground_truth_vulnerable,
            "security_rationale": self.explanation,
        }

        import json
        return {
            "messages": [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": user_content.strip()},
                {"role": "assistant", "content": json.dumps(assistant_content, indent=2)},
            ]
        }
