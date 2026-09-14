#!/usr/bin/env python3
"""
VAJRA LoRA Merger & GGUF Exporter
Merges fine-tuned LoRA adapter weights into the base Qwen2.5-Coder model
so it can be run standalone or converted to GGUF for Ollama.
"""

import os
import sys
import argparse

def merge_lora(base_model_name: str, adapter_path: str, output_dir: str):
    print("=" * 70)
    print(" ❖ VAJRA LoRA Adapter Merger")
    print("=" * 70)

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
    except ImportError:
        print("[!] Missing dependencies. Run: pip install torch transformers peft")
        sys.exit(1)

    print(f"[1/4] Loading Tokenizer from: {base_model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)

    print(f"[2/4] Loading Base Model in FP16 precision...")
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        torch_dtype=torch.float16,
        device_map="cpu", # safe for CPU merging
        trust_remote_code=True
    )

    print(f"[3/4] Attaching and Merging LoRA Adapter from: {adapter_path}...")
    model = PeftModel.from_pretrained(base_model, adapter_path)
    merged_model = model.merge_and_unload()

    print(f"[4/4] Saving Standalone Merged Model to: {output_dir}...")
    os.makedirs(output_dir, exist_ok=True)
    merged_model.save_pretrained(output_dir, safe_serialization=True)
    tokenizer.save_pretrained(output_dir)

    print("\n" + "=" * 70)
    print(f" ✓ Successfully merged! Model saved to: {output_dir}")
    print(" You can now run this model directly or convert to GGUF for Ollama.")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="Merge VAJRA LoRA Adapter into Base Model")
    parser.add_argument("--base-model", type=str, default="Qwen/Qwen2.5-Coder-7B-Instruct", help="Base model name or path")
    parser.add_argument("--adapter", type=str, required=True, help="Path to downloaded LoRA adapter folder")
    parser.add_argument("--output", type=str, default="./vajra_merged_model", help="Directory to save merged weights")
    args = parser.parse_args()

    merge_lora(args.base_model, args.adapter, args.output)

if __name__ == "__main__":
    main()
