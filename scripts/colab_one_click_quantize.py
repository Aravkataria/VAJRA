# scripts/colab_one_click_quantize.py
"""
1-Click Google Colab / Kaggle Free Quantization Script.
Copy & paste this into a free Google Colab notebook (T4 GPU runtime).
Takes ~6 minutes total. 100% Free. Uses 0 MB of your home internet data.
"""

COLAB_CELL_CODE = '''# ==============================================================================
# 🚀 1-CLICK VAJRA 7B GGUF QUANTIZATION (FREE GOOGLE COLAB T4 GPU)
# ==============================================================================
# 1. Go to "Runtime" -> "Change runtime type" -> Select "T4 GPU" (Free)
# 2. Run this cell. Enter your Hugging Face Token (with WRITE permissions) when prompted.
# ==============================================================================

!pip install -q transformers peft torch accelerate huggingface_hub gguf sentencepiece protobuf

import os, gc, torch
from huggingface_hub import HfApi, login
from getpass import getpass
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    HF_TOKEN = getpass("🔑 Enter Hugging Face Access Token (WRITE permissions): ").strip()
login(token=HF_TOKEN)

BASE_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
LORA_MODEL = "AravKataria/vajra-lora"
MERGED_DIR = "./vajra_merged_7b"

print("🔒 Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, token=HF_TOKEN, trust_remote_code=True)
tokenizer.save_pretrained(MERGED_DIR)

print("🔒 Loading base model in float16...")
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    token=HF_TOKEN,
    torch_dtype=torch.float16,
    device_map="auto",
    low_cpu_mem_usage=True,
    trust_remote_code=True
)

print("🔒 Merging fine-tuned LoRA weights...")
model = PeftModel.from_pretrained(base_model, LORA_MODEL, token=HF_TOKEN)
merged = model.merge_and_unload()
merged.save_pretrained(MERGED_DIR)
print("✅ LoRA weights successfully merged into standalone checkpoint!")

del base_model, model, merged
gc.collect()
torch.cuda.empty_cache()

print("⚙️ Building llama.cpp tools...")
!git clone https://github.com/ggerganov/llama.cpp.git
!cd llama.cpp && cmake -B build && cmake --build build --config Release -j$(nproc)
!pip install -q -r llama.cpp/requirements.txt

print("📦 Converting merged checkpoint to intermediate FP16 GGUF...")
!python llama.cpp/convert_hf_to_gguf.py ./vajra_merged_7b --outtype f16 --outfile vajra-7b-f16.gguf

print("⚡ Quantizing to 4-bit Q4_K_M (~4.2 GB)...")
!./llama.cpp/build/bin/llama-quantize vajra-7b-f16.gguf vajra-7b-q4_k_m.gguf Q4_K_M
!rm -f vajra-7b-f16.gguf

DEST_REPO = "AravKataria/vajra-7b-gguf"
print(f"🚀 Uploading vajra-7b-q4_k_m.gguf to Hugging Face ({DEST_REPO})...")
api = HfApi(token=HF_TOKEN)
api.create_repo(repo_id=DEST_REPO, repo_type="model", exist_ok=True)
api.upload_file(
    path_or_fileobj="vajra-7b-q4_k_m.gguf",
    path_in_repo="vajra-7b-q4_k_m.gguf",
    repo_id=DEST_REPO,
    repo_type="model",
    commit_message="Add 4-bit Q4_K_M quantized GGUF weights (~4.2 GB)"
)

print("\\n" + "="*65)
print("🎉 SUCCESS! Compressed VAJRA 7B GGUF Model is live on Hugging Face:")
print(f"👉 https://huggingface.co/{DEST_REPO}")
print("="*65)
'''

if __name__ == "__main__":
    print(COLAB_CELL_CODE)
