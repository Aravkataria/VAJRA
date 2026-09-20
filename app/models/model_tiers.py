# app/models/model_tiers.py

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ModelTier(str, Enum):
    ULTRA_LITE = "ultra_lite"   # Tier 1: Qwen2.5-Coder-0.5B (<500MB RAM, Render/Free hosting)
    STANDARD = "standard"       # Tier 2: Qwen2.5-Coder-7B Q4 GGUF (<4.8GB RAM, HF 16GB CPU Space)
    MAX = "max"                 # Tier 3: AravKataria/vajra-lora 7B (Full precision, ZeroGPU / High-end GPU)


@dataclass(frozen=True)
class ModelTierConfig:
    tier: ModelTier
    display_name: str
    parameter_size: str
    target_environment: str
    max_tokens: int
    typical_latency_ms: int
    ram_footprint_mb: int
    has_quota_limit: bool
    description: str


TIER_CONFIGS = {
    ModelTier.ULTRA_LITE: ModelTierConfig(
        tier=ModelTier.ULTRA_LITE,
        display_name="VAJRA Ultra-Lite",
        parameter_size="0.5B",
        target_environment="Render Free Tier (512MB RAM) / Native CPU",
        max_tokens=2048,
        typical_latency_ms=1200,
        ram_footprint_mb=450,
        has_quota_limit=False,
        description="Fast STEM concepts, definitions, general syntax, and lightweight logic.",
    ),
    ModelTier.STANDARD: ModelTierConfig(
        tier=ModelTier.STANDARD,
        display_name="VAJRA Standard",
        parameter_size="7B (Quantized Q4_K_M)",
        target_environment="Hugging Face CPU Basic (16GB RAM) - Free Forever",
        max_tokens=4096,
        typical_latency_ms=3500,
        ram_footprint_mb=4500,
        has_quota_limit=False,
        description="Standard code auditing, multi-function refactoring, and CWE security classification.",
    ),
    ModelTier.MAX: ModelTierConfig(
        tier=ModelTier.MAX,
        display_name="VAJRA Max (Autonomous Reasoning)",
        parameter_size="7B LoRA (Full Precision)",
        target_environment="Hugging Face ZeroGPU / Local High-End GPU",
        max_tokens=8192,
        typical_latency_ms=4500,
        ram_footprint_mb=14000,
        has_quota_limit=True,
        description="Autonomous 6-stage sentinel dynamic proofs, zero-regression patch repair, and deep AST invariant solving.",
    ),
}
