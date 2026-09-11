# training/model2_patch_generator/schema.py
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RepairStrategy(str, Enum):
    PARAMETERIZATION = "parameterization"
    INPUT_SANITIZATION = "input_sanitization"
    SAFE_API_SUBSTITUTION = "safe_api_substitution"
    AUTHORIZATION_CHECK = "authorization_check"
    BOUNDS_ENFORCEMENT = "bounds_enforcement"
    SAFE_DESERIALIZATION = "safe_deserialization"
    HARD_NEGATIVE_NOOP = "hard_negative_noop"


@dataclass
class PatchTrainingSample:
    sample_id: str
    language: str
    cwe_id: str
    vulnerability_category: str
    strategy: RepairStrategy
    vulnerable_code: str
    repaired_code: str
    unified_diff: str
    diagnostic_message: str
    target_file: str
    start_line: int
    end_line: int
    ast_invariants: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_chatml_messages(self) -> List[Dict[str, str]]:
        system_prompt = (
            "You are VAJRA Model 2: Sovereign Neural Patch Synthesizer & Code Repair Engine. "
            "Your objective is to ingest vulnerable source code alongside AST diagnostics and synthesize "
            "a minimal, sound, syntax-preserving repair that eradicates the vulnerability without altering "
            "unrelated business logic or introducing regressions."
        )
        
        user_content = (
            f"### Vulnerability Diagnostic\n"
            f"- File: {self.target_file}\n"
            f"- Language: {self.language}\n"
            f"- CWE: {self.cwe_id} ({self.vulnerability_category})\n"
            f"- Lines: {self.start_line}-{self.end_line}\n"
            f"- Finding: {self.diagnostic_message}\n\n"
            f"### Vulnerable Code Snippet\n"
            f"```{self.language}\n"
            f"{self.vulnerable_code}\n"
            f"```\n\n"
            f"Synthesize the repaired code and unified patch diff preserving all AST invariants."
        )
        
        assistant_content = (
            f"### Repaired Code\n"
            f"```{self.language}\n"
            f"{self.repaired_code}\n"
            f"```\n\n"
            f"### Unified Patch Diff\n"
            f"```diff\n"
            f"{self.unified_diff}\n"
            f"```"
        )
        
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content}
        ]
