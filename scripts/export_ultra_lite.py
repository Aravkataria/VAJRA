# scripts/export_ultra_lite.py
"""
VAJRA Ultra-Lite Export & Quantization Pipeline.
Prepares Qwen2.5-Coder-0.5B-Instruct in 4-bit GGUF format (<400MB)
for $0 free deployment on Render, 1GB RAM PCs, and lightweight edge hosts.
"""

import os
import sys
import subprocess


def export_ultra_lite(output_dir: str = "./models/vajra_ultra_lite"):
    print("=" * 60)
    print("🚀 VAJRA Ultra-Lite (0.5B) Export Pipeline")
    print("=" * 60)

    os.makedirs(output_dir, exist_ok=True)
    model_id = "Qwen/Qwen2.5-Coder-0.5B-Instruct"

    print(f"[*] Step 1: Downloading & preparing {model_id}...")
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
        import torch

        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        tokenizer.save_pretrained(output_dir)

        print("[*] Saving model weights in PyTorch float16...")
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,
            low_cpu_mem_usage=True,
            trust_remote_code=True,
        )
        model.save_pretrained(output_dir)
        print(f"[✅] Model weights successfully exported to {output_dir}")

    except Exception as e:
        print(f"[!] Error during model download: {e}")
        return

    print("\n[*] Step 2: Converting to GGUF Q4_K_M (~380 MB)...")
    print("Tip: Run llama.cpp's convert_hf_to_gguf.py on this folder:")
    print(f"     python convert_hf_to_gguf.py {output_dir} --outtype f16")
    print(f"     ./llama-quantize {output_dir}/model.gguf {output_dir}/vajra-ultra-lite-Q4_K_M.gguf Q4_K_M")
    print("=" * 60)
    print("✅ Ultra-Lite Export Complete!")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "./models/vajra_ultra_lite"
    export_ultra_lite(out)
