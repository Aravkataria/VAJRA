# app/repair/ai_repair.py

import ast
import difflib
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from app.analysis.python_static import analyze_source
from app.decision.decision import Decision
from app.repair.model_provider import RepairModelProvider
from app.repair.ollama_repair_provider import OllamaRepairProvider
from app.repair.patch import Patch
from app.repair.repair_model import RepairModel

logger = logging.getLogger(__name__)


class AIRepairer(RepairModel):
    """Generate and deterministically validate an AI repair candidate."""

    REQUIRED_FIELDS = {
        "should_patch",
        "confidence",
        "description",
        "strategy",
        "limitations",
    }

    def __init__(self, provider: RepairModelProvider | None = None):
        self.provider = provider or OllamaRepairProvider()
        self.last_reason = "not_attempted"
        self.last_data: Optional[dict[str, Any]] = None
        self.last_response_excerpt: Optional[str] = None
        self.last_provider_metadata: dict[str, Any] = {}

    def repair(self, decision: Decision, workspace_path: Path) -> Optional[Patch]:
        self.last_reason = "not_applicable"
        self.last_data = None
        self.last_response_excerpt = None
        self.last_provider_metadata = {}

        if decision.route != "reasoning":
            return None

        evidence = decision.evidence
        source_path = self._safe_source_path(workspace_path, evidence.file)
        if source_path is None:
            self.last_reason = "unsafe_patch_path"
            return None

        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as exc:
            self.last_reason = f"could_not_read_source: {exc}"
            self._debug(self.last_reason, evidence)
            return None

        prompt = self._build_prompt(decision, source)

        try:
            response = self.provider.generate(prompt)
            self.last_response_excerpt = response[:2000]
            self.last_provider_metadata = dict(
                getattr(self.provider, "last_metadata", {}) or {}
            )
        except Exception as exc:
            self.last_reason = f"provider_error: {exc}"
            self._debug(self.last_reason, evidence)
            return None

        try:
            return self._parse_response(response, evidence, source)
        except Exception as exc:
            self.last_reason = f"invalid_ai_repair: {exc}"
            self._debug(self.last_reason, evidence)
            return None

    def _safe_source_path(self, workspace_path: Path, relative_file: str) -> Optional[Path]:
        root = Path(workspace_path).resolve()
        candidate = (root / relative_file).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return None
        if not candidate.is_file():
            return None
        return candidate

    def _debug(self, reason: str, evidence, data: Optional[dict] = None):
        if os.environ.get("VAJRA_REPAIR_DEBUG", "").lower() in {"1", "true", "yes", "on"}:
            logger.info(
                "AIRepairer %s @ %s:%s | model_data=%s | provider=%s | response=%r",
                reason,
                evidence.file,
                evidence.line,
                data,
                self.last_provider_metadata,
                self.last_response_excerpt,
            )

    @staticmethod
    def _quote_untrusted(value: Any) -> str:
        return repr(value)

    @staticmethod
    def _feedback_block(feedback: Optional[str]) -> str:
        if not feedback:
            return ""
        return f"""
PREVIOUS ATTEMPT FEEDBACK
A prior patch attempt for this exact finding was rejected during
verification. Do not propose the same fix again -- it did not work.
Reason it was rejected: {AIRepairer._quote_untrusted(feedback)}
Propose a materially different repair strategy that specifically
avoids this problem, or decline if you cannot.
"""

    @staticmethod
    def _failure_memory_block(vulnerability_type: str, file: Optional[str] = None) -> str:
        try:
            from app.storage.db import get_db
            memories = get_db().get_failure_memory(vulnerability_type, file)
            if not memories:
                return ""
            items = []
            for m in memories[:3]:
                stage = m.get("final_method") or "verifier"
                reason = m.get("final_reason") or m.get("outcome_reason") or "rejected"
                items.append(f"- Past attempt for {vulnerability_type} was rejected by {stage}: {reason}")
            return f"""
HISTORICAL LESSONS (FAILURE MEMORY)
The following past repair attempts for this vulnerability type failed verification:
{chr(10).join(items)}
Do NOT repeat these failure patterns. Propose an alternative valid fix.
"""
        except Exception:
            return ""

    def _build_prompt(self, decision: Decision, source: str) -> str:
        e = decision.evidence
        return f"""
You are VAJRA's security repair model. You are proposing a candidate patch,
not executing code and not modifying files.

Return ONLY one JSON object. No markdown and no code fences.

{self._feedback_block(decision.feedback)}
{self._failure_memory_block(e.vulnerability_type, e.file)}

EVIDENCE
file={self._quote_untrusted(e.file)}
vulnerability_type={self._quote_untrusted(e.vulnerability_type)}
severity={self._quote_untrusted(e.severity)}

SOURCE FILE
{source}
"""

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:].strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
                text = "\n".join(lines[1:-1]).strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                return json.loads(text[start : end + 1])
            raise ValueError("Model response did not contain a valid JSON object.")

    def _parse_response(self, response_text: str, evidence, source: str) -> Optional[Patch]:
        data = self._extract_json(response_text)
        self.last_data = data

        if not isinstance(data, dict):
            raise ValueError("Response is not a JSON dictionary.")

        missing = sorted(self.REQUIRED_FIELDS - set(data))
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        should_patch = data.get("should_patch")
        if not isinstance(should_patch, bool):
            raise ValueError("should_patch must be a boolean.")

        if not should_patch:
            reason = str(data.get("decline_reason") or data.get("description") or "model declined")
            self.last_reason = f"model_declined: {reason}"
            self._debug(self.last_reason, evidence, data)
            return None

        confidence = float(data.get("confidence", 0.0))
        if confidence < 0.70:
            raise ValueError(f"Model confidence {confidence:.2f} is below 0.70 threshold.")

        patched_source = data.get("patched_source", "")
        if not isinstance(patched_source, str) or not patched_source.strip():
            raise ValueError("patched_source cannot be empty when should_patch=true.")

        if patched_source.strip() == source.strip():
            self.last_reason = "model_proposed_no_change"
            return None

        try:
            ast.parse(patched_source, filename=evidence.file)
        except SyntaxError as exc:
            raise ValueError(f"Patched source has syntax error: {exc.msg} at line {exc.lineno}")

        original_findings = analyze_source(evidence.file, source)
        candidate_findings = analyze_source(evidence.file, patched_source)

        orig_types = [f.vulnerability_type for f in original_findings if f.vulnerability_type == evidence.vulnerability_type]
        cand_types = [f.vulnerability_type for f in candidate_findings if f.vulnerability_type == evidence.vulnerability_type]

        if len(cand_types) >= len(orig_types) and len(orig_types) > 0:
            raise ValueError(f"Candidate did not remove target vulnerability {evidence.vulnerability_type}")

        self.last_reason = "patch_proposed"
        return Patch.from_source_change(
            file=evidence.file,
            line=evidence.line,
            original_source=source,
            patched_source=patched_source,
            description=str(data.get("description") or "AI proposed patch"),
            confidence=confidence,
            strategy=str(data.get("strategy") or "ai-reasoning"),
            vulnerability_type=evidence.vulnerability_type,
            call_name=getattr(evidence, "call_name", None),
        )