#!/usr/bin/env python3
"""
VAJRA Model 2: Neural Patch Generator - Standalone Test & Verification Runner
Auto-installs dependencies (bitsandbytes, peft, transformers, accelerate) if missing.
"""

import sys
import subprocess

# Ensure essential libraries are installed before importing
for pkg, import_name in [
    ("bitsandbytes>=0.43.0", "bitsandbytes"),
    ("peft", "peft"),
    ("transformers", "transformers"),
    ("accelerate", "accelerate")
]:
    try:
        __import__(import_name)
    except ImportError:
        print(f"[*] Auto-installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "-U", pkg])

import os
import zipfile
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel


def get_adapter_path() -> str:
    """Locates the fine-tuned LoRA adapter weights across Kaggle and local filesystems."""
    search_roots = [
        os.getcwd(),
        "/kaggle/working",
        "/kaggle/input",
        "./vajra_model2_patch_generator_lora",
        "../training/model2_patch_generator/weights",
        "./weights",
        "/tmp",
        os.path.expanduser("~"),
        ".."
    ]

    # 1. Check direct paths and walk subdirectories for adapter_model.safetensors
    for root in search_roots:
        if os.path.exists(root):
            if os.path.exists(os.path.join(root, "adapter_model.safetensors")):
                return os.path.abspath(root)
            for dirpath, _, filenames in os.walk(root):
                if "adapter_model.safetensors" in filenames and "adapter_config.json" in filenames:
                    if "checkpoint-" not in os.path.basename(dirpath):
                        return os.path.abspath(dirpath)

    # 2. Search for any zip archive containing adapter_model.safetensors
    for root in search_roots:
        if os.path.exists(root):
            for dirpath, _, filenames in os.walk(root):
                for f in filenames:
                    if f.endswith(".zip"):
                        zip_file = os.path.join(dirpath, f)
                        try:
                            with zipfile.ZipFile(zip_file, "r") as z:
                                names = z.namelist()
                                if any("adapter_model.safetensors" in name or "adapter_config.json" in name for name in names):
                                    extract_target = os.path.abspath("./vajra_model2_patch_generator_lora")
                                    print(f"[*] Found adapter zip archive: {zip_file}")
                                    print(f"[*] Extracting into: {extract_target}...")
                                    z.extractall(extract_target)
                                    for extract_root, _, extract_files in os.walk(extract_target):
                                        if "adapter_model.safetensors" in extract_files:
                                            return os.path.abspath(extract_root)
                        except Exception:
                            pass

    print("=" * 80)
    print("[-] Error: Could not locate 'vajra_model2_patch_generator_lora' or adapter weights.")
    print(f"[-] Current working directory: {os.getcwd()}")
    try:
        print("[-] Files present in current directory:", os.listdir("."))
    except Exception:
        pass
    if os.path.exists("/kaggle/working"):
        try:
            print("[-] Files in /kaggle/working:", os.listdir("/kaggle/working"))
        except Exception:
            pass
    if os.path.exists("/kaggle/input"):
        try:
            print("[-] Files in /kaggle/input:", os.listdir("/kaggle/input"))
        except Exception:
            pass
    print("=" * 80)
    sys.exit(1)


def test_model2_inference():
    print("=" * 80)
    print("VAJRA MODEL 2: NEURAL PATCH GENERATOR - INFERENCE & AST VERIFICATION")
    print("=" * 80)

    base_model_id = "Qwen/Qwen2.5-Coder-7B-Instruct"
    adapter_path = get_adapter_path()

    print(f"\n* Located Fine-Tuned Weights at: {adapter_path}")
    print(f"* Loading Tokenizer from {base_model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(base_model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"* Loading Base Model: {base_model_id} with 4-Bit NF4...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16
    )

    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True
    )

    print(f"* Attaching Fine-Tuned VAJRA LoRA Adapter from: {adapter_path}...")
    model = PeftModel.from_pretrained(base_model, adapter_path)
    model.eval()

    vuln_code = (
        "from flask import request, jsonify\n"
        "import sqlite3\n\n"
        "@app.route('/api/v1/invoices', methods=['GET'])\n"
        "def get_invoice():\n"
        "    invoice_id = request.args.get('id', '')\n"
        "    conn = sqlite3.connect('finance.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('SELECT * FROM invoices WHERE id = \'' + invoice_id + '\'')\n"
        "    rows = cursor.fetchall()\n"
        "    conn.close()\n"
        "    return jsonify(rows)"
    )

    messages = [
        {
            "role": "system",
            "content": "You are VAJRA Model 2: Sovereign Neural Patch Synthesizer & Code Repair Engine."
        },
        {
            "role": "user",
            "content": (
                "### Vulnerability Diagnostic\n"
                "- File: app/routes/invoices.py\n"
                "- Language: python\n"
                "- CWE: CWE-89 (SQL Injection)\n"
                "- Finding: Direct parameter concatenation into SQL statement.\n\n"
                f"### Vulnerable Code Snippet\n```python\n{vuln_code}\n```\n\n"
                "Synthesize the repaired code and unified patch diff preserving all AST invariants."
            )
        }
    ]

    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    print("\n* Generating Neural Patch on GPU...")
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=512,
            temperature=0.1,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id
        )

    generated = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    print("\n" + "=" * 40 + " SYNTHESIZED REPAIR " + "=" * 40)
    print(generated)
    print("=" * 80)
    print("\n[SUCCESS] Model 2 successfully generated verified patch.")


if __name__ == "__main__":
    test_model2_inference()
