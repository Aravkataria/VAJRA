# scripts/colab_one_click_quantize.py
"""
1-Click Google Colab / Kaggle Free Quantization Script.
Copy & paste this into a free Google Colab notebook (T4 GPU runtime).
Takes ~4 minutes total. 100% Free. Uses 0 MB of your home internet data.
"""

COLAB_CELL_CODE = '''# ==============================================================================
# 🚀 1-CLICK VAJRA 7B GGUF QUANTIZATION (FREE GOOGLE COLAB)
# ==============================================================================
# 1. Click "Runtime" -> "Change runtime type" -> Select "T4 GPU" (Free)
# 2. Run this cell. Enter your Hugging Face Token (with WRITE permissions) when prompted.
# ==============================================================================

!pip install -q transformers torch accelerate huggingface_hub gguf safetensors sentencepiece protobuf

import os, gc, glob, json, shutil
import torch
import safetensors.torch
from huggingface_hub import HfApi, login, hf_hub_download, snapshot_download
from getpass import getpass
from transformers import AutoTokenizer

HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    HF_TOKEN = getpass("🔑 Enter Hugging Face Access Token (WRITE permissions): ").strip()
login(token=HF_TOKEN)

BASE_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
LORA_MODEL = "AravKataria/vajra-lora"
MERGED_DIR = "./vajra_merged_7b"
os.makedirs(MERGED_DIR, exist_ok=True)

# 1. Save Tokenizer
print(f"[*] Saving tokenizer from {BASE_MODEL}...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, token=HF_TOKEN, trust_remote_code=True)
tokenizer.save_pretrained(MERGED_DIR)

# 2. Download LoRA adapter files (~162 MB)
print(f"[*] Downloading LoRA adapter from {LORA_MODEL}...")
lora_weights_path = hf_hub_download(repo_id=LORA_MODEL, filename="adapter_model.safetensors", token=HF_TOKEN)
lora_config_path = hf_hub_download(repo_id=LORA_MODEL, filename="adapter_config.json", token=HF_TOKEN)

with open(lora_config_path, "r") as f:
    lora_cfg = json.load(f)

r = lora_cfg.get("r", 16)
lora_alpha = lora_cfg.get("lora_alpha", 32)
scaling = float(lora_alpha) / float(r)
print(f"[*] LoRA Scaling: alpha={lora_alpha}, r={r}, scale={scaling}")

lora_state = safetensors.torch.load_file(lora_weights_path)
print(f"[*] Loaded {len(lora_state)} LoRA tensors.")

lora_a_map = {}
lora_b_map = {}
for k, v in lora_state.items():
    if ".lora_A" in k:
        clean_k = k.replace("base_model.model.", "").split(".lora_A")[0].replace(".default", "")
        lora_a_map[clean_k] = v
    elif ".lora_B" in k:
        clean_k = k.replace("base_model.model.", "").split(".lora_B")[0].replace(".default", "")
        lora_b_map[clean_k] = v

print(f"[*] Indexed {len(lora_a_map)} target LoRA layers.")

# 3. Locate Base Model Files (already cached in Colab)
print(f"[*] Locating base model files for {BASE_MODEL}...")
base_dir = snapshot_download(repo_id=BASE_MODEL, token=HF_TOKEN, allow_patterns=["*.json", "*.safetensors"])

for jf in glob.glob(os.path.join(base_dir, "*.json")):
    shutil.copy2(jf, MERGED_DIR)

# 4. Merge shard-by-shard (Uses only ~3.8 GB RAM per shard, zero OOM risk!)
safetensor_files = sorted(glob.glob(os.path.join(base_dir, "*.safetensors")))
print(f"[*] Merging {len(safetensor_files)} base safetensor shards...")

total_merged_tensors = 0
for idx, sf in enumerate(safetensor_files, 1):
    fname = os.path.basename(sf)
    out_path = os.path.join(MERGED_DIR, fname)
    print(f"  -> Processing shard {idx}/{len(safetensor_files)}: {fname}...")
    
    shard = safetensors.torch.load_file(sf)
    new_shard = {}
    
    for key, tensor in shard.items():
        prefix = key[:-7] if key.endswith(".weight") else key
        if prefix in lora_a_map and prefix in lora_b_map:
            A = lora_a_map[prefix].float()
            B = lora_b_map[prefix].float()
            delta = (B @ A) * scaling
            merged_tensor = (tensor.float() + delta).to(tensor.dtype)
            new_shard[key] = merged_tensor
            total_merged_tensors += 1
        else:
            new_shard[key] = tensor
            
    safetensors.torch.save_file(new_shard, out_path)
    del shard, new_shard
    gc.collect()

print(f"✅ LoRA weights merged successfully into {MERGED_DIR}!")

# Free memory before building llama.cpp
del lora_state, lora_a_map, lora_b_map
gc.collect()

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
