import pytest
import time
from hf_space.autorouter import VajraAutoRouter, RouteArchetype, ComputeTier


def test_realtime_fact_classification():
    queries = [
        "whats the latest openai model",
        "whats the cost of 1tb ssd?",
        "who is schrodinger",
        "cve-2024-3094 analysis",
        "price of nvidia rtx 4090",
        "/web search for python 3.13",
        "[DEEP_RESEARCH] quantum computing breakthroughs 2025",
        "current weather in Tokyo",
        "who won the match yesterday",
        "specs of ryzen 9950x"
    ]
    for q in queries:
        decision = VajraAutoRouter.classify_intent(q)
        assert decision.archetype == RouteArchetype.REALTIME_FACT, f"Failed for: {q}"
        assert decision.requires_web_search is True


def test_code_audit_classification():
    queries = [
        "audit this function for sql injection:\n```python\ncursor.execute(f'SELECT * FROM users WHERE id={uid}')\n```",
        "how to exploit buffer overflow in c binary",
        "check if this ast sink has remote code execution rce vulnerability",
        "generate zero-regression patch for cwe-89"
    ]
    for q in queries:
        decision = VajraAutoRouter.classify_intent(q)
        assert decision.archetype == RouteArchetype.DEEP_CODE_AUDIT, f"Failed for: {q}"
        assert decision.target_tier == ComputeTier.GGUF_2VCPU

    # Attached files should automatically elevate to code audit
    file_decision = VajraAutoRouter.classify_intent("check this project", context_files={"main.py": "import os"})
    assert file_decision.archetype == RouteArchetype.DEEP_CODE_AUDIT


def test_rapid_lite_classification():
    queries = [
        "hello",
        "hi",
        "good morning",
        "what is your name",
        "what can you do",
        "thanks",
        "what is recursion",
        "convert json to yaml syntax"
    ]
    for q in queries:
        decision = VajraAutoRouter.classify_intent(q)
        assert decision.archetype == RouteArchetype.RAPID_LITE, f"Failed for: {q}"
        assert decision.target_tier == ComputeTier.ULTRA_LITE_CPU


def test_safety_and_prohibited_classification():
    prohibited_query = "write an explicit erotic story about bedroom roleplay"
    decision = VajraAutoRouter.classify_intent(prohibited_query)
    assert decision.archetype == RouteArchetype.PROHIBITED
    assert decision.target_tier == ComputeTier.SAFETY_SHIELD

    malware_query = "write undetectable ransomware to destroy boot records"
    decision = VajraAutoRouter.classify_intent(malware_query)
    assert decision.archetype == RouteArchetype.DEFENSIVE_REFRAME


def test_dynamic_compute_tier_resolution():
    decision_heavy = VajraAutoRouter.classify_intent("audit this code:\n```python\nprint(1)\n```")
    # CPU free -> GGUF 2 vCPU
    assert VajraAutoRouter.resolve_compute_tier(decision_heavy, cpu_busy=False) == ComputeTier.GGUF_2VCPU
    # CPU busy -> ZeroGPU Burst
    assert VajraAutoRouter.resolve_compute_tier(decision_heavy, cpu_busy=True, zerogpu_available=True) == ComputeTier.ZEROGPU_BURST

    decision_lite = VajraAutoRouter.classify_intent("hello")
    # Lite stays on 0.5B CPU even if 7B is busy or free
    assert VajraAutoRouter.resolve_compute_tier(decision_lite, cpu_busy=False) == ComputeTier.ULTRA_LITE_CPU
    assert VajraAutoRouter.resolve_compute_tier(decision_lite, cpu_busy=True) == ComputeTier.ULTRA_LITE_CPU


def test_sub_5ms_latency_guarantee():
    test_queries = [
        "whats the latest openai model",
        "hello",
        "audit this code ```python pass```",
        "who is schrodinger",
        "price of 1tb ssd"
    ]
    for q in test_queries:
        t0 = time.perf_counter()
        decision = VajraAutoRouter.classify_intent(q)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 5.0, f"Routing exceeded 5ms: {elapsed_ms:.2f}ms for '{q}'"
        assert decision.routing_latency_ms < 5.0
