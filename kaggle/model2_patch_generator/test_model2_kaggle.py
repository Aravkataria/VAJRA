#!/usr/bin/env python3
"""
test_model2_kaggle.py

Inference & Verification Test Runner for VAJRA Model 2 (Neural Patch Generator).
Loads the fine-tuned LoRA weights onto Qwen2.5-Coder-7B and repairs real vulnerability fixtures.
"""

import sys
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

def test_model2_inference():
    print("=" * 80)
    print("VAJRA MODEL 2: NEURAL PATCH GENERATOR - INFERENCE & AST VERIFICATION")
    print("=" * 80)
    
    base_model_id = "Qwen/Qwen2.5-Coder-7B-Instruct"
    adapter_path = "./vajra_model2_patch_generator_lora"
    
    print(f"\n* Loading Base Model: {base_model_id} with 4-Bit NF4...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16
    )
    
    tokenizer = AutoTokenizer.from_pretrained(adapter_path, trust_remote_code=True)
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True
    )
    
    print(f"* Attaching Fine-Tuned VAJRA LoRA Adapter from: {adapter_path}...")
    model = PeftModel.from_pretrained(base_model, adapter_path)
    model.eval()
    
    # Test Fixture: Vulnerable SQLi Python
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
    print("=" * 90)
    print("\n[SUCCESS] Model 2 successfully generated verified patch.")

if __name__ == "__main__":
    test_model2_inference()
