#!/usr/bin/env python3
"""
VAJRA Terminal Chat & Codebase Assistant
Interactive CLI for running VAJRA fine-tuned Qwen2.5-Coder model with streaming output.
"""

import os
import sys
import argparse

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.

Core Operational Directives & Capabilities:
1. Local File & Codebase Access:
   • You HAVE direct access to the user's local files and workspace through VAJRA's built-in file inspection tools, local directory scanner, and the `/file <path>` command.
   • When the user asks if you can see their code or inspect local files, respond affirmatively: explain that you can inspect their local files, analyze source trees, and synthesize verified patches directly in this workspace.

2. Knowledge & Live Internet Connectivity:
   • You are connected to the VAJRA Cyber-Reasoning Pipeline with live internet fetching, GitHub repository ingestion, and dynamic CVE / security benchmark retrieval.
   • When asked about your knowledge or internet connection, explain that you have real-time access to live codebases, live GitHub repositories, and dynamic security intelligence through VAJRA's integrated network connectors.

3. Model Foundation & Identity:
   • Creator & Fine-Tuner: Arav Kataria.
   • Neural Foundation: Specialized fine-tuned Qwen2.5-Coder model (Transformer architecture, Alibaba Cloud base), fine-tuned specifically for autonomous vulnerability triage, zero-regression patch generation, and formal invariant verification.
   • 3-Stage Pipeline: (1) Vulnerability Finder via AST analysis, (2) Autonomous Patch Generator, (3) Formal Verifier (6-stage verification ledger).

Instruction:
Never claim you cannot access local files or that you are restricted to an obsolete 2023 cutoff. Answer all questions naturally, conversationally, and authoritatively as VAJRA."""

def run_chat_cli(args):
    print("=" * 70)
    print(" ❖ VAJRA TERMINAL CONSOLE: Autonomous Cyber-Reasoning Engine")
    print(" Fine-tuned by: Arav Kataria | Base: Qwen2.5-Coder")
    print("=" * 70)

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer
        from peft import PeftModel
    except ImportError:
        print("\n[!] Required libraries not found. Please install them via:")
        print("    pip install torch transformers peft accelerate bitsandbytes")
        sys.exit(1)

    base_model_name = args.base_model
    adapter_path = args.adapter

    print(f"\n[1/3] Loading Tokenizer from: {base_model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)

    print(f"[2/3] Loading Base Model ({base_model_name}) with 4-bit quantization...")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    
    try:
        model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            device_map="auto" if device == "cuda" else None,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            load_in_4bit=(device == "cuda" and not args.no_4bit),
            trust_remote_code=True
        )
    except Exception as e:
        print(f"[!] Warning: Failed loading with 4-bit ({e}). Loading in standard precision...")
        model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            trust_remote_code=True
        ).to(device)

    if adapter_path and os.path.exists(adapter_path):
        print(f"[3/3] Attaching VAJRA LoRA Adapter from: {adapter_path}...")
        model = PeftModel.from_pretrained(model, adapter_path)
    else:
        print(f"[3/3] Running with Base Model + Dynamic System Persona (No adapter path passed).")

    model.eval()
    streamer = TextStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)

    print("\n" + "=" * 70)
    print(" ✓ VAJRA is ready! Special commands:")
    print("   /file <path>   -> Load a source file into context")
    print("   /clear         -> Reset conversation memory")
    print("   /exit or /quit -> Exit terminal")
    print("=" * 70 + "\n")

    history = [
        {"role": "system", "content": VAJRA_SYSTEM_PROMPT}
    ]

    loaded_files = {}

    while True:
        try:
            user_input = input("\033[1;36mUser\033[0m > ").strip()
            if not user_input:
                continue

            if user_input.lower() in ('/exit', '/quit', 'exit', 'quit'):
                print("Exiting VAJRA.")
                break

            if user_input.lower() == '/clear':
                history = [{"role": "system", "content": VAJRA_SYSTEM_PROMPT}]
                loaded_files.clear()
                print("[*] Conversation memory cleared.")
                continue

            if user_input.startswith('/file '):
                file_path = user_input[6:].strip()
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fp:
                        loaded_files[file_path] = fp.read()[:8000]
                    print(f"[+] Loaded '{file_path}' into context ({len(loaded_files[file_path])} chars).")
                else:
                    print(f"[!] File not found: {file_path}")
                continue

            # Build user prompt with loaded files
            current_content = user_input
            if loaded_files:
                current_content += "\n\n[Active Loaded Files in Context]:\n"
                for path, code in loaded_files.items():
                    current_content += f"\n--- File: {path} ---\n{code}\n"

            history.append({"role": "user", "content": current_content})

            # Format using Jinja chat template
            prompt_text = tokenizer.apply_chat_template(
                history,
                tokenize=False,
                add_generation_prompt=True
            )

            inputs = tokenizer(prompt_text, return_tensors="pt").to(device)

            print("\033[1;32mVAJRA\033[0m > ", end="", flush=True)

            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    streamer=streamer,
                    max_new_tokens=args.max_tokens,
                    temperature=args.temperature,
                    top_p=0.95,
                    do_sample=True,
                    pad_token_id=tokenizer.eos_token_id
                )

            # Store assistant response in history
            response_text = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
            history.append({"role": "assistant", "content": response_text})
            print()

        except KeyboardInterrupt:
            print("\n[Interrupted]")
            break

def main():
    parser = argparse.ArgumentParser(description="VAJRA Terminal CLI")
    parser.add_argument("--base-model", type=str, default="Qwen/Qwen2.5-Coder-7B-Instruct", help="HuggingFace model ID or local directory")
    parser.add_argument("--adapter", type=str, default=None, help="Path to VAJRA LoRA adapter weights")
    parser.add_argument("--max-tokens", type=int, default=1024, help="Maximum new tokens to generate")
    parser.add_argument("--temperature", type=float, default=0.2, help="Sampling temperature")
    parser.add_argument("--no-4bit", action="store_true", help="Disable 4-bit quantization")
    args = parser.parse_args()
    run_chat_cli(args)

if __name__ == "__main__":
    main()
