# scripts/export_vajra_gguf.py
"""
VAJRA Standard & Max GGUF Export Pipeline.
1. Merges AravKataria/vajra-lora with base Qwen2.5-Coder-7B-Instruct foundation.
2. Exports merged standalone weights.
3. Converts to GGUF format and quantizes to Q4_K_M (~4.3 GB) and Q3_K_M (~3.5 GB).
4. Compatible with free Google Colab (T4 GPU), Kaggle, or local machine.
"""

import os
import sys


def merge_and_export_gguf(
    base_model_id: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
    lora_model_id: str = "AravKataria/vajra-lora",
    merged_output_dir: str = "./models/vajra_coder_7b_merged",
):
    print("=" * 65)
    print("🛡️ VAJRA LoRA Merge & GGUF Quantization Pipeline")
    print("=" * 65)

    os.makedirs(merged_output_dir, exist_ok=True)
    hf_token = os.environ.get("HF_TOKEN")

    print(f"[*] Step 1: Loading Tokenizer from {lora_model_id}...")
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
        import torch

        try:
            tokenizer = AutoTokenizer.from_pretrained(lora_model_id, token=hf_token, trust_remote_code=True)
        except Exception:
            tokenizer = AutoTokenizer.from_pretrained(base_model_id, token=hf_token, trust_remote_code=True)
        tokenizer.save_pretrained(merged_output_dir)

        print(f"[*] Step 2: Loading Base Model ({base_model_id}) in float16...")
        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_id,
            token=hf_token,
            torch_dtype=torch.float16,
            device_map="auto",
            low_cpu_mem_usage=True,
            trust_remote_code=True,
        )

        print(f"[*] Step 3: Merging fine-tuned LoRA adapter from {lora_model_id}...")
        model = PeftModel.from_pretrained(base_model, lora_model_id, token=hf_token)
        merged_model = model.merge_and_unload()
        print("[✅] LoRA weights successfully merged into base 7B foundation!")

        print(f"[*] Step 4: Saving standalone merged weights to {merged_output_dir}...")
        merged_model.save_pretrained(merged_output_dir)
        print(f"[✅] Standalone merged checkpoint saved at {merged_output_dir}")

    except Exception as e:
        print(f"[!] Error during LoRA merge: {e}")
        return

    print("\n" + "=" * 65)
    print("📋 NEXT STEPS FOR ZERO-COST GGUF QUANTIZATION (via llama.cpp):")
    print("=" * 65)
    print("1. Clone llama.cpp:")
    print("   git clone https://github.com/ggerganov/llama.cpp.git && cd llama.cpp && cmake -B build && cmake --build build --config Release")
    print("\n2. Convert merged model to GGUF format:")
    print(f"   python convert_hf_to_gguf.py {merged_output_dir} --outtype f16 --outfile vajra-7b-f16.gguf")
    print("\n3. Quantize to Q4_K_M (4.3 GB — Best balance of speed & reasoning):")
    print("   ./build/bin/llama-quantize vajra-7b-f16.gguf vajra-coder-7b-Q4_K_M.gguf Q4_K_M")
    print("\n4. (Optional) Quantize to Q3_K_M (3.5 GB — Ultra compact):")
    print("   ./build/bin/llama-quantize vajra-7b-f16.gguf vajra-coder-7b-Q3_K_M.gguf Q3_K_M")
    print("\n5. Upload to Hugging Face Hub (Free Unlimited Storage):")
    print("   huggingface-cli upload AravKataria/vajra-coder-7b-GGUF vajra-coder-7b-Q4_K_M.gguf")
    print("=" * 65)


if __name__ == "__main__":
    merge_and_export_gguf()
