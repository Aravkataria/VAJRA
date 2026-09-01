#!/usr/bin/env python3
"""
scripts/fine_tune_repairer.py

Sovereign Fine-Tuning Pipeline for Tier-2 Repair Model.

Reads verified training pairs from VAJRA's Adaptive Learning Engine,
formats them into standard instruction-tuning format, and prepares
the dataset for LoRA / QLoRA fine-tuning.

Usage:
    python scripts/fine_tune_repairer.py --export-only
    python scripts/fine_tune_repairer.py --dataset data/vajra_cwe_dataset.jsonl --model Qwen/Qwen2.5-Coder-7B-Instruct
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.storage.adaptive_learning import AdaptiveLearningEngine


def export_dataset(output_path: Path) -> int:
    engine = AdaptiveLearningEngine()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = engine.export_fine_tuning_dataset(output_path)
    print(f"[✓] Successfully exported {count} verified 6-stage repair pairs to: {output_path}")
    return count


def main():
    parser = argparse.ArgumentParser(description="VAJRA Tier-2 Repair Model Sovereign Fine-Tuning Pipeline")
    parser.add_argument("--export-only", action="store_true", help="Only export dataset from Adaptive Learning graph")
    parser.add_argument("--output", type=str, default="data/vajra_training_dataset.jsonl", help="Dataset output path")
    parser.add_argument("--base-model", type=str, default="Qwen/Qwen2.5-Coder-7B-Instruct", help="Base model for LoRA")

    args = parser.parse_args()
    out_file = Path(args.output)

    count = export_dataset(out_file)

    if args.export_only:
        return

    print(f"\n[INFO] Dataset prepared for base model: {args.base_model}")
    print(f"[INFO] Recommended LoRA Hyperparameters:")
    print(f"       • Rank (r): 16")
    print(f"       • Alpha: 32")
    print(f"       • Learning Rate: 2e-4")
    print(f"       • Target Modules: ['q_proj', 'k_proj', 'v_proj', 'o_proj']")
    print(f"\n[✓] When ready to fine-tune on GPU, execute with unsloth / trl.")


if __name__ == "__main__":
    main()
