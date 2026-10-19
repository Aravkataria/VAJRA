import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple


class RouteArchetype:
    PROHIBITED = "prohibited"
    DEFENSIVE_REFRAME = "defensive_reframe"
    REALTIME_FACT = "realtime_fact"
    DEEP_CODE_AUDIT = "deep_code_audit"
    RAPID_LITE = "rapid_lite"
    STANDARD_REASONING = "standard_reasoning"


class ComputeTier:
    SAFETY_SHIELD = "safety_shield"
    ULTRA_LITE_CPU = "0.5b_cpu"
    GGUF_2VCPU = "7b_gguf_2vcpu"
    ZEROGPU_BURST = "7b_zerogpu_burst"
    HF_ROUTER = "hf_router_api"


@dataclass
class RouteDecision:
    archetype: str
    target_tier: str
    clean_query: str
    requires_web_search: bool = False
    deep_research: bool = False
    prefer_google: bool = True
    reason: str = ""
    routing_latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class VajraAutoRouter:
    """
    Intelligent Pre-Flight Query Classifier & Dynamic Compute Dispatcher.
    Determines query archetype, required grounding layer, and optimal hardware tier
    in sub-5ms with zero external API calls.
    """

    REALTIME_FACT_REGEX = re.compile(
        r"\b("
        r"search(\s+the)?\s+web|look\s+up|latest|news|today|yesterday|recent|current\s+events?|"
        r"cve-\d{4}-\d+|vulnerability\s+report|zero-?day|security\s+advisory|"
        r"release\s+notes?|changelog|version\s+\d+|who\s+won|score|price|pricing|"
        r"cost(\s+of)?|how\s+much(\s+is|\s+does|\s+cost)?|rates?|quote|buy|specs|"
        r"specifications?|benchmarks?|worth|ssd|gpu|cpu|ram|hardware|laptop|phone|"
        r"weather|president|prime\s+minister|ceo\s+of|founded|who\s+is|who\s+was|"
        r"what\s+happened|when\s+was|documentation\s+for|official\s+docs|github\s+repo\s+of|"
        r"2024|2025|2026|newest|patch\s+notes|in\s+the\s+wild|"
        r"openai(\s+model)?|anthropic|claude|gemini|deepseek|llama\s+\d+|qwen|"
        r"schrodinger"
        r")\b",
        re.IGNORECASE
    )

    CODE_AUDIT_REGEX = re.compile(
        r"\b("
        r"audit|vulnerability|vulnerabilities|cwe-\d+|ast\s+scan|buffer\s+overflow|"
        r"sql\s+injection|xss|csrf|ssrf|remote\s+code\s+execution|rce|reverse\s+shell|"
        r"rop\s+chain|heap\s+spray|format\s+string|memory\s+leak|race\s+condition|"
        r"patch\s+this|fix\s+this\s+code|secure\s+implementation|decompile|disassemble|"
        r"penetration\s+test|exploit\s+analysis|static\s+analysis|taint\s+analysis|"
        r"defensive\s+patch|zero-regression|code\s+review"
        r")\b",
        re.IGNORECASE
    )

    CONVERSATIONAL_QUICK_REGEX = re.compile(
        r"^(?:hi|hello|hey|greetings|good\s+(?:morning|afternoon|evening)|"
        r"who\s+are\s+you|what\s+is\s+your\s+name|what\s+can\s+you\s+do|"
        r"thanks|thank\s+you|bye|goodbye|how\s+are\s+you|"
        r"help|test|ping)$",
        re.IGNORECASE
    )

    HARD_BAN_PATTERNS = [
        "child sexual", "csam", "pedophil", "non-consensual sexual violence"
    ]

    DESTRUCTIVE_MALWARE_PATTERNS = [
        "undetectable ransomware", "corporate ransomware", "disk wiper",
        "destroy boot records", "mbr wiper", "destructive wiper"
    ]

    NSFW_EROTIC_PATTERNS = [
        "erotic roleplay", "erotic story", "bedroom roleplay", "write erotica",
        "pornographic story", "explicit sexual narrative"
    ]

    @classmethod
    def classify_intent(
        cls,
        prompt: str,
        context_files: Optional[Dict[str, str]] = None,
        force_web_search: bool = False,
        deep_research: bool = False,
        prefer_google: bool = True
    ) -> RouteDecision:
        t0 = time.perf_counter()
        raw = (prompt or "").strip()
        lowered = raw.lower()

        # 1. Safety & Harm Pre-Flight Check (<1ms)
        for pat in cls.HARD_BAN_PATTERNS:
            if pat in lowered:
                return RouteDecision(
                    archetype=RouteArchetype.PROHIBITED,
                    target_tier=ComputeTier.SAFETY_SHIELD,
                    clean_query=raw,
                    reason="hard_ban_prohibited",
                    routing_latency_ms=(time.perf_counter() - t0) * 1000
                )

        for pat in cls.DESTRUCTIVE_MALWARE_PATTERNS:
            if pat in lowered:
                return RouteDecision(
                    archetype=RouteArchetype.DEFENSIVE_REFRAME,
                    target_tier=ComputeTier.GGUF_2VCPU,
                    clean_query=raw,
                    reason="destructive_malware_reframe",
                    routing_latency_ms=(time.perf_counter() - t0) * 1000
                )

        for pat in cls.NSFW_EROTIC_PATTERNS:
            if pat in lowered:
                return RouteDecision(
                    archetype=RouteArchetype.PROHIBITED,
                    target_tier=ComputeTier.SAFETY_SHIELD,
                    clean_query=raw,
                    reason="nsfw_erotica_prohibited",
                    routing_latency_ms=(time.perf_counter() - t0) * 1000
                )

        # 2. Tag-based directives
        if "[DEEP_RESEARCH]" in raw:
            deep_research = True
            force_web_search = True
        if "[LIVE_SEARCH]" in raw:
            force_web_search = True

        clean_p = re.sub(r"\[(?:DEEP_RESEARCH|LIVE_SEARCH)\]\s*", "", raw).strip()

        # 3. Real-Time Fact / Recency Search Detection
        explicit_search = bool(re.search(
            r"^(?:/(?:search|web|browse|lookup|internet)|search(?:\s+(?:the\s+web|the\s+internet|for))?|look\s+up|google)\s+(.+)$",
            clean_p,
            re.IGNORECASE
        ))
        has_search_intent = explicit_search or force_web_search or deep_research or bool(cls.REALTIME_FACT_REGEX.search(clean_p))

        if has_search_intent:
            return RouteDecision(
                archetype=RouteArchetype.REALTIME_FACT,
                target_tier=ComputeTier.GGUF_2VCPU,
                clean_query=clean_p,
                requires_web_search=True,
                deep_research=deep_research,
                prefer_google=prefer_google,
                reason="realtime_fact_retrieval",
                routing_latency_ms=(time.perf_counter() - t0) * 1000
            )

        # 4. Deep Code Audit & AST Verification Detection
        has_code_block = "```" in clean_p or (context_files and len(context_files) > 0)
        has_audit_keywords = bool(cls.CODE_AUDIT_REGEX.search(clean_p))
        if has_code_block or has_audit_keywords:
            return RouteDecision(
                archetype=RouteArchetype.DEEP_CODE_AUDIT,
                target_tier=ComputeTier.GGUF_2VCPU,
                clean_query=clean_p,
                requires_web_search=False,
                reason="deep_ast_code_audit",
                routing_latency_ms=(time.perf_counter() - t0) * 1000
            )

        # 5. Rapid Speculative Lite Detection (<150ms instant response)
        is_conversational = bool(cls.CONVERSATIONAL_QUICK_REGEX.match(clean_p.strip()))
        is_short_general = len(clean_p) < 140 and "\n" not in clean_p and not has_code_block
        if is_conversational or is_short_general:
            return RouteDecision(
                archetype=RouteArchetype.RAPID_LITE,
                target_tier=ComputeTier.ULTRA_LITE_CPU,
                clean_query=clean_p,
                requires_web_search=False,
                reason="rapid_speculative_lite",
                routing_latency_ms=(time.perf_counter() - t0) * 1000
            )

        # 6. Standard In-Depth Technical Reasoning (Default)
        return RouteDecision(
            archetype=RouteArchetype.STANDARD_REASONING,
            target_tier=ComputeTier.GGUF_2VCPU,
            clean_query=clean_p,
            requires_web_search=False,
            reason="standard_technical_reasoning",
            routing_latency_ms=(time.perf_counter() - t0) * 1000
        )

    @classmethod
    def resolve_compute_tier(
        cls,
        decision: RouteDecision,
        cpu_busy: bool = False,
        zerogpu_available: bool = True
    ) -> str:
        """
        Dynamically binds the decision to the optimal compute engine based on runtime load.
        """
        if decision.archetype == RouteArchetype.PROHIBITED:
            return ComputeTier.SAFETY_SHIELD

        if decision.archetype == RouteArchetype.RAPID_LITE:
            return ComputeTier.ULTRA_LITE_CPU

        # For heavy jobs (Code Audit, Realtime Fact, Standard Technical)
        if cpu_busy:
            if zerogpu_available:
                return ComputeTier.ZEROGPU_BURST
            return ComputeTier.ULTRA_LITE_CPU

        return ComputeTier.GGUF_2VCPU

    @classmethod
    def format_telemetry(
        cls,
        decision: RouteDecision,
        actual_model: str,
        total_time_ms: float,
        sources_count: int = 0
    ) -> Dict[str, Any]:
        return {
            "archetype": decision.archetype,
            "target_tier": decision.target_tier,
            "actual_model": actual_model,
            "web_grounded": sources_count > 0,
            "sources_count": sources_count,
            "routing_latency_ms": round(decision.routing_latency_ms, 2),
            "total_latency_ms": round(total_time_ms, 2),
            "reason": decision.reason
        }
