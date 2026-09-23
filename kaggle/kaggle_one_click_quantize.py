# kaggle/kaggle_one_click_quantize.py
"""
VAJRA 7B GGUF Quantization Pipeline for Kaggle Notebooks.
Uses /tmp for high-capacity 70+ GB storage so Kaggle never runs out of disk space.
"""

KAGGLE_CODE = '''# ==============================================================================
# 🚀 VAJRA 7B GGUF 4-BIT QUANTIZATION FOR KAGGLE
# ==============================================================================
# 📌 Instructions for Kaggle:
# 1. In the right sidebar: Settings -> Internet -> Turn ON!
# 2. Accelerator: None (CPU, 30 GB RAM) or GPU T4 x2 / P100 (Free)
# 3. Paste this cell and click "Run".
# ==============================================================================

# Clean up any leftover files from previous attempts to guarantee maximum free space
!rm -rf /kaggle/working/* /tmp/vajra* /tmp/llama.cpp

!pip install -q transformers torch accelerate huggingface_hub gguf safetensors sentencepiece protobuf

import os, gc, glob, json, shutil
import torch
import safetensors.torch
from huggingface_hub import HfApi, login, hf_hub_download, snapshot_download
from getpass import getpass
from transformers import AutoTokenizer

# 1. Hugging Face Authentication
HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    try:
        from kaggle_secrets import UserSecretsClient
        user_secrets = UserSecretsClient()
        HF_TOKEN = user_secrets.get_secret("HF_TOKEN")
    except Exception:
        pass

if not HF_TOKEN:
    HF_TOKEN = getpass("🔑 Enter your Hugging Face Access Token (WRITE permissions): ").strip()

login(token=HF_TOKEN)
print("✅ Authenticated with Hugging Face!")

BASE_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
LORA_MODEL = "AravKataria/vajra-lora"

# Use /tmp for intermediate files (70+ GB capacity, avoids Kaggle /working 20 GB limit)
MERGED_DIR = "/tmp/vajra_merged_7b"
LLAMA_DIR = "/tmp/llama.cpp"
F16_GGUF = "/tmp/vajra-7b-f16.gguf"
FINAL_GGUF = "/kaggle/working/vajra-7b-q4_k_m.gguf"

os.makedirs(MERGED_DIR, exist_ok=True)

# 2. Save Tokenizer
print(f"[*] Saving tokenizer from {BASE_MODEL}...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, token=HF_TOKEN, trust_remote_code=True)
tokenizer.save_pretrained(MERGED_DIR)

# 3. Download LoRA adapter (~162 MB)
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

# 4. Download Base Model Shards
print(f"[*] Downloading base model shards for {BASE_MODEL}...")
base_dir = snapshot_download(repo_id=BASE_MODEL, token=HF_TOKEN, allow_patterns=["*.json", "*.safetensors"])

for jf in glob.glob(os.path.join(base_dir, "*.json")):
    shutil.copy2(jf, MERGED_DIR)

# 5. Merge shard-by-shard into /tmp/vajra_merged_7b
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

# Free memory before llama.cpp build
del lora_state, lora_a_map, lora_b_map
gc.collect()

# 6. Fast Build llama-quantize in /tmp
print("⚙️ Building llama-quantize tool...")
!git clone https://github.com/ggerganov/llama.cpp.git {LLAMA_DIR}
!cd {LLAMA_DIR} && cmake -B build -DGGML_BUILD_TESTS=OFF -DGGML_BUILD_EXAMPLES=OFF && cmake --build build --target llama-quantize -j$(nproc)
!pip install -q -r {LLAMA_DIR}/requirements.txt

# 7. Convert to intermediate FP16 GGUF in /tmp
print("📦 Converting merged checkpoint to intermediate FP16 GGUF...")
!python {LLAMA_DIR}/convert_hf_to_gguf.py {MERGED_DIR} --outtype f16 --outfile {F16_GGUF}

# IMMEDIATELY delete merged safetensors directory to free 15 GB of disk space before quantizing
print("🧹 Removing raw safetensors shards to free disk...")
shutil.rmtree(MERGED_DIR, ignore_errors=True)

# 8. Quantize to 4-bit Q4_K_M (~4.2 GB) directly into /kaggle/working
print("⚡ Quantizing to 4-bit Q4_K_M (~4.2 GB)...")
!{LLAMA_DIR}/build/bin/llama-quantize {F16_GGUF} {FINAL_GGUF} Q4_K_M

# Delete intermediate 15 GB F16 GGUF file
!rm -f {F16_GGUF}
!rm -rf {LLAMA_DIR}

print("✅ Quantization complete! Final model ready:")
!ls -lh {FINAL_GGUF}

# 9. Upload Quantized GGUF Model to Hugging Face
DEST_REPO = "AravKataria/vajra-7b-gguf"
print(f"🚀 Uploading vajra-7b-q4_k_m.gguf to Hugging Face ({DEST_REPO})...")
api = HfApi(token=HF_TOKEN)
api.create_repo(repo_id=DEST_REPO, repo_type="model", exist_ok=True)
api.upload_file(
    path_or_fileobj=FINAL_GGUF,
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
    print(KAGGLE_CODE)
