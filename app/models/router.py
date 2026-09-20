# app/models/router.py

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple
from app.models.model_tiers import ModelTier, TIER_CONFIGS, ModelTierConfig


# Explicit keywords that demand deep multi-stage autonomous proofs (Tier 3)
MAX_TIER_TRIGGERS = [
    "deep reasoning",
    "formal verification",
    "zero-regression",
    "sentinel proof",
    "proof ledger",
    "dynamic sentinel",
    "invariant proof",
    "autonomous patch generation",
    "full pipeline audit",
    "taint analyzer proof",
]

# Security keywords that indicate moderate complexity requiring 7B (Tier 2)
STANDARD_TIER_TRIGGERS = [
    "vulnerability",
    "cwe-",
    "cve-",
    "sql injection",
    "cross-site",
    "buffer overflow",
    "remote code execution",
    "security audit",
    "threat model",
    "taint analysis",
    "refactor this code",
    "generate unit tests",
]


class ComplexityRouter:
    """
    Cascading Complexity Classifier & Query Dispatcher.
    Determines the minimum viable model tier required for a given query to:
    1. Deliver rapid responses for general STEM / syntax inquiries (<1.5s).
    2. Prevent ZeroGPU quota exhaustion by reserving heavy GPU for Level 3.
    3. Keep memory footprint strictly within the deployment environment.
    """

    @classmethod
    def evaluate(
        cls,
        prompt: str,
        files: Optional[Dict[str, str]] = None,
        requested_tier: Optional[str] = None,
    ) -> Tuple[ModelTier, str]:
        """
        Returns (selected_tier, reasoning_explanation)
        """
        # 1. Manual user override if requested
        if requested_tier:
            req_clean = requested_tier.lower().strip()
            for tier in ModelTier:
                if tier.value == req_clean:
                    return tier, f"User explicitly requested tier '{tier.value}'"

        prompt_clean = prompt.strip()
        lowered = prompt_clean.lower()
        word_count = len(prompt_clean.split())
        file_count = len(files) if files else 0
        total_code_lines = 0
        if files:
            for content in files.values():
                total_code_lines += len(content.splitlines())

        # 2. Check for Level 3 (Max) triggers
        if any(trigger in lowered for trigger in MAX_TIER_TRIGGERS):
            return (
                ModelTier.MAX,
                "Query requests deep autonomous formal verification or multi-stage sentinel proofs.",
            )

        if file_count >= 3 or total_code_lines > 400:
            return (
                ModelTier.MAX,
                f"Multi-file codebase context ({file_count} files, {total_code_lines} lines) requires high-capacity 7B reasoning.",
            )

        # 3. Check for Level 2 (Standard) triggers
        if any(trigger in lowered for trigger in STANDARD_TIER_TRIGGERS):
            return (
                ModelTier.STANDARD,
                "Query involves cybersecurity triage, vulnerability assessment, or code refactoring.",
            )

        if file_count > 0 or total_code_lines > 25:
            return (
                ModelTier.STANDARD,
                f"Code context attached ({file_count} files, {total_code_lines} lines) requires standard 7B code comprehension.",
            )

        # 4. Check for Level 1 (Ultra-Lite) indicators
        # General STEM definitions, laws, math, greetings, simple questions, short queries
        is_stem_or_general = any(
            re.search(pat, lowered)
            for pat in [
                r"\bwhat is\b",
                r"\bwho discovered\b",
                r"\bexplain\b",
                r"\bformula\b",
                r"\blaw\b",
                r"\btheorem\b",
                r"\bkirchhoff\b",
                r"\bohm\b",
                r"\bnewton\b",
                r"\bmath\b",
                r"\bphysics\b",
                r"\bhello\b",
                r"\bhi\b",
                r"\bhow to write\b",
                r"\bsyntax\b",
                r"\bexample of\b",
            ]
        )

        if is_stem_or_general or word_count <= 100:
            return (
                ModelTier.ULTRA_LITE,
                "General conceptual inquiry or lightweight prompt suitable for zero-quota Ultra-Lite engine.",
            )

        # Default fallback for unclassified medium-length queries
        return (
            ModelTier.STANDARD,
            "Standard complexity query routed to 7B general reasoning model.",
        )


def route_query(
    prompt: str,
    files: Optional[Dict[str, str]] = None,
    requested_tier: Optional[str] = None,
) -> Tuple[ModelTier, ModelTierConfig, str]:
    tier, reason = ComplexityRouter.evaluate(prompt, files, requested_tier)
    config = TIER_CONFIGS[tier]
    return tier, config, reason
