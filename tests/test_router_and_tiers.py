# tests/test_router_and_tiers.py

import pytest
from app.models.model_tiers import ModelTier, TIER_CONFIGS
from app.models.router import ComplexityRouter, route_query


def test_tier_configs_exist():
    assert ModelTier.ULTRA_LITE in TIER_CONFIGS
    assert ModelTier.STANDARD in TIER_CONFIGS
    assert ModelTier.MAX in TIER_CONFIGS

    ultra = TIER_CONFIGS[ModelTier.ULTRA_LITE]
    assert ultra.ram_footprint_mb < 500
    assert ultra.has_quota_limit is False

    std = TIER_CONFIGS[ModelTier.STANDARD]
    assert std.ram_footprint_mb < 5000
    assert std.has_quota_limit is False

    max_tier = TIER_CONFIGS[ModelTier.MAX]
    assert max_tier.has_quota_limit is True


def test_router_general_stem_to_ultra_lite():
    queries = [
        "what is kirchhoff's law who discovered it",
        "explain Ohm's law with an example",
        "what is Newton's third law",
        "how to reverse a string in python",
        "hello vajra, how are you today?",
    ]
    for q in queries:
        tier, config, reason = route_query(q)
        assert tier == ModelTier.ULTRA_LITE, f"Expected ULTRA_LITE for '{q}', got {tier}"
        assert config.ram_footprint_mb < 500


def test_router_vulnerability_to_standard():
    queries = [
        "Audit this code for SQL injection vulnerabilities",
        "Is there a CWE-79 cross-site scripting issue here?",
        "Please refactor this code and generate unit tests",
    ]
    for q in queries:
        tier, config, reason = route_query(q, files={"main.py": "def handle(req): pass"})
        assert tier == ModelTier.STANDARD, f"Expected STANDARD for '{q}', got {tier}"


def test_router_deep_sentinel_to_max():
    queries = [
        "Run formal verification on this patch",
        "Execute 6-stage dynamic sentinel proof ledger",
        "Perform autonomous zero-regression patch repair",
    ]
    for q in queries:
        tier, config, reason = route_query(q)
        assert tier == ModelTier.MAX, f"Expected MAX for '{q}', got {tier}"


def test_router_explicit_override():
    tier, config, reason = route_query("what is 1 + 1", requested_tier="max")
    assert tier == ModelTier.MAX
    assert "explicitly requested" in reason

    tier2, _, _ = route_query("Audit this zero-day exploit", requested_tier="ultra_lite")
    assert tier2 == ModelTier.ULTRA_LITE
