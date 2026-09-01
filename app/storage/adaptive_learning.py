# app/storage/adaptive_learning.py

"""
Phase 7: Long-Term Adaptive Learning & Outcome Tracking Engine.

Records successful 6-stage verified repairs, causal invariants, and failed attempts
into an auditable knowledge graph (.vajra/knowledge_graph.json).

Allows future scans across different repositories to instantly retrieve proven
remediation patterns (0ms fast path) and exports structured datasets for fine-tuning.
"""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class VerifiedRepairMemory:
    pattern_id: str
    vulnerability_type: str
    original_sink_snippet: str
    verified_patch_snippet: str
    causal_intent_invariant: str
    mutation_kill_score: float
    verification_passed_stages: int
    repository: str
    recorded_at: str
    success_count: int = 1


@dataclass
class FailedRepairMemory:
    pattern_id: str
    vulnerability_type: str
    failed_patch_snippet: str
    rejection_stage: str
    rejection_reason: str
    repository: str
    recorded_at: str


class AdaptiveLearningEngine:
    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or Path(os.environ.get("VAJRA_HOME", Path.home() / ".vajra"))
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.knowledge_path = self.storage_dir / "knowledge_graph.json"
        self._load_knowledge()

    def _load_knowledge(self):
        self.verified_repairs: Dict[str, Dict[str, Any]] = {}
        self.failed_attempts: List[Dict[str, Any]] = []

        if self.knowledge_path.is_file():
            try:
                with open(self.knowledge_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.verified_repairs = data.get("verified_repairs", {})
                    self.failed_attempts = data.get("failed_attempts", [])
            except Exception:
                self.verified_repairs = {}
                self.failed_attempts = []

    def _save_knowledge(self):
        try:
            with open(self.knowledge_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "total_verified_patterns": len(self.verified_repairs),
                        "total_failed_patterns": len(self.failed_attempts),
                        "verified_repairs": self.verified_repairs,
                        "failed_attempts": self.failed_attempts[-50:], # Keep recent 50 failures
                    },
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def record_success(
        self,
        vulnerability_type: str,
        sink_snippet: str,
        patch_snippet: str,
        intent_invariant: str,
        repository: str = "local",
    ):
        """Records a 6-stage verified patch into persistent memory."""
        pattern_id = f"{vulnerability_type}:{hash(sink_snippet.strip())}"

        if pattern_id in self.verified_repairs:
            self.verified_repairs[pattern_id]["success_count"] += 1
            self.verified_repairs[pattern_id]["recorded_at"] = datetime.now(timezone.utc).isoformat()
        else:
            self.verified_repairs[pattern_id] = asdict(
                VerifiedRepairMemory(
                    pattern_id=pattern_id,
                    vulnerability_type=vulnerability_type,
                    original_sink_snippet=sink_snippet.strip(),
                    verified_patch_snippet=patch_snippet.strip(),
                    causal_intent_invariant=intent_invariant,
                    mutation_kill_score=100.0,
                    verification_passed_stages=6,
                    repository=repository,
                    recorded_at=datetime.now(timezone.utc).isoformat(),
                )
            )

        self._save_knowledge()

    def record_failure(
        self,
        vulnerability_type: str,
        failed_patch: str,
        rejection_stage: str,
        rejection_reason: str,
        repository: str = "local",
    ):
        """Records a rejected patch attempt to prevent repeating the mistake."""
        pattern_id = f"{vulnerability_type}:{hash(failed_patch.strip())}"
        self.failed_attempts.append(
            asdict(
                FailedRepairMemory(
                    pattern_id=pattern_id,
                    vulnerability_type=vulnerability_type,
                    failed_patch_snippet=failed_patch.strip(),
                    rejection_stage=rejection_stage,
                    rejection_reason=rejection_reason,
                    repository=repository,
                    recorded_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        )
        self._save_knowledge()

    def query_verified_pattern(self, vulnerability_type: str, sink_snippet: str) -> Optional[str]:
        """Queries learned memory for a proven 6-stage verified repair."""
        pattern_id = f"{vulnerability_type}:{hash(sink_snippet.strip())}"
        record = self.verified_repairs.get(pattern_id)
        if record:
            return record.get("verified_patch_snippet")
        return None

    def export_fine_tuning_dataset(self, output_file: Path) -> int:
        """Exports verified repairs into JSONL format for fine-tuning the Tier-2 Repair Model."""
        count = 0
        with open(output_file, "w", encoding="utf-8") as f:
            for pattern_id, record in self.verified_repairs.items():
                prompt = (
                    f"### VULNERABILITY EVIDENCE:\n"
                    f"Type: {record['vulnerability_type']}\n"
                    f"Sink Snippet: {record['original_sink_snippet']}\n"
                    f"Causal Intent Invariant: {record['causal_intent_invariant']}\n\n"
                    f"### MINIMAL VERIFIED REPAIR DIFF:\n"
                )
                completion = record["verified_patch_snippet"]
                f.write(json.dumps({"prompt": prompt, "completion": completion}) + "\n")
                count += 1
        return count
