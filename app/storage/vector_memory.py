# app/storage/vector_memory.py

"""
Software-Engineering Memory Architecture for VAJRA.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z_]\w*", text.lower()))


def _jaccard_similarity(set1: set[str], set2: set[str]) -> float:
    if not set1 or not set2:
        return 0.0
    return len(set1 & set2) / len(set1 | set2)


@dataclass
class MemoryRecord:
    record_id: str
    vulnerability_type: str
    code_snippet: str
    patch_diff: str
    verified: bool
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SoftwareEngineeringMemory:
    def __init__(self):
        self._records: List[MemoryRecord] = []

    def add_record(
        self,
        record_id: str,
        vulnerability_type: str,
        code_snippet: str,
        patch_diff: str,
        verified: bool,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._records.append(
            MemoryRecord(
                record_id=record_id,
                vulnerability_type=vulnerability_type,
                code_snippet=code_snippet,
                patch_diff=patch_diff,
                verified=verified,
                reason=reason,
                metadata=metadata or {},
            )
        )

    def retrieve_similar_repairs(
        self,
        vulnerability_type: str,
        query_code: str,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        query_tokens = _tokenize(query_code)
        matches = []

        for record in self._records:
            if record.vulnerability_type != vulnerability_type:
                continue

            record_tokens = _tokenize(record.code_snippet)
            score = _jaccard_similarity(query_tokens, record_tokens)

            matches.append({
                "record_id": record.record_id,
                "vulnerability_type": record.vulnerability_type,
                "patch_diff": record.patch_diff,
                "verified": record.verified,
                "reason": record.reason,
                "similarity_score": score,
            })

        matches.sort(key=lambda x: (x["verified"], x["similarity_score"]), reverse=True)
        return matches[:top_k]


_default_memory: Optional[SoftwareEngineeringMemory] = None


def get_memory() -> SoftwareEngineeringMemory:
    global _default_memory
    if _default_memory is None:
        _default_memory = SoftwareEngineeringMemory()
    return _default_memory