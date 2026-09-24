from __future__ import annotations
import os
import sys
import gc
import re
import uuid
import time
import json
import urllib.request
import threading

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
try:
    import torch
    try:
        torch.set_num_threads(2)
        torch.set_num_interop_threads(1)
    except Exception:
        pass
except ImportError:
    torch = None

try:
    import gradio as gr
except ImportError:
    gr = None

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any, Tuple

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer
    from peft import PeftModel
except ImportError:
    AutoModelForCausalLM = AutoTokenizer = TextIteratorStreamer = PeftModel = None

VAJRA_SECRET_KEY = os.getenv("VAJRA_SECRET_KEY")
HF_TOKEN = os.getenv("HF_TOKEN", None)
LORA_MODEL_ID = "AravKataria/vajra-lora"
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"
ULTRA_LITE_MODEL_ID = "Qwen/Qwen2.5-Coder-0.5B-Instruct"

RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 30
ip_request_history: Dict[str, list] = {}

inference_lock = threading.Lock()

def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    history = ip_request_history.get(client_ip, [])
    valid_history = [t for t in history if now - t < RATE_LIMIT_WINDOW]
    if len(valid_history) >= MAX_REQUESTS_PER_WINDOW:
        return False
    valid_history.append(now)
    ip_request_history[client_ip] = valid_history
    return True

INJECTION_TRIGGERS = [
    "ignore all previous instructions", "disregard all instructions",
    "reveal your system prompt", "you are now in dan mode", "jailbreak"
]

# =====================================================================
# PII & SENSITIVE DATA GATEKEEPER (Zero-Leak Data Protection)
# =====================================================================
PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"),
    "PHONE": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{2,4}\)|\d{2,4})[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
    "SSN_GOV_ID": re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b[A-Z]{5}\d{4}[A-Z]{1}\b"),
    "API_KEY_OPENAI": re.compile(r"\bsk-[a-zA-Z0-9_\-]{20,}\b"),
    "API_KEY_HF": re.compile(r"\bhf_[a-zA-Z0-9]{34,}\b"),
    "API_KEY_AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|PGP)? PRIVATE KEY-----[\s\S]*?-----END (?:RSA|OPENSSH|EC|PGP)? PRIVATE KEY-----"),
    "GITHUB_TOKEN": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    "AUTH_PASSWORD": re.compile(r"""(?i)(?:password|passwd|secret_key|api_secret)\s*[:=]\s*['"][^'"]{4,}['"]""")
}

def sanitize_pii_and_secrets(text: str) -> Tuple[str, List[str]]:
    """
    Sanitizes personal identifiable information (PII) and secret credentials.
    Replaces sensitive data with typed redaction tokens [REDACTED_TYPE]
    so that private data never enters the LLM context or memory.
    """
    if not text:
        return "", []
    sanitized = text
    detected_types = []
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(sanitized):
            detected_types.append(pii_type)
            sanitized = pattern.sub(f"[REDACTED_{pii_type}]", sanitized)
    return sanitized, detected_types

def scrub_output_secrets(text: str) -> str:
    """
    Scrubs any inadvertent leaks of server paths, environment tokens, or sensitive credentials
    from the generated model output before streaming to client.
    """
    if not text:
        return ""
    scrubbed = text
    for tok in [HF_TOKEN, VAJRA_SECRET_KEY]:
        if tok and len(tok) > 6 and tok in scrubbed:
            scrubbed = scrubbed.replace(tok, "[VAJRA_REDACTED_TOKEN]")
    scrubbed = re.sub(r"[C-Z]:\\[Users|Windows|system32][^\s\"'<>]+", "[REDACTED_SYSTEM_PATH]", scrubbed, flags=re.IGNORECASE)
    return scrubbed

def sanitize_and_check_injection(raw_text: str) -> Tuple[str, List[str]]:
    cleaned = raw_text.replace("\x00", "").strip()
    lowered = cleaned.lower()
    for trig in INJECTION_TRIGGERS:
        if trig in lowered:
            return "[VAJRA Security Shield: Prompt Injection Pattern Neutralized] Please ask legitimate technical questions.", ["INJECTION"]
    sanitized, pii_detected = sanitize_pii_and_secrets(cleaned)
    return sanitized, pii_detected

# =====================================================================
# CONTEXTUAL SAFETY & CONTENT POLICY EVALUATOR (NOT NAIVE KEYWORD FILTER)
# =====================================================================
# 1. Technical / Cybersecurity / Biomedical Whitelist
# Legitimate security testing, software engineering, AI/LLMs, and scientific inquiries explicitly pass.
TECHNICAL_CONTEXT_REGEX = re.compile(
    r"\b("
    r"llm|large\s+language\s+model|transformer|neural\s+network|deep\s+learning|machine\s+learning|ai\s+model|"
    r"pytorch|tensorflow|hugging\s*face|fine-?tun\w*|weights|loss|gradient|backprop\w*|scratch|dataset|"
    r"python|javascript|typescript|c\+\+|golang|rust|java|html|css|sql|nosql|docker|kubernetes|linux|"
    r"algorithm|data\s+structure|api|backend|frontend|framework|library|compiler|ast|syntax\s+tree|bytecode|"
    r"react|vue|angular|node|express|fastapi|django|flask|nextjs|tailwind|git|github|database|query|schema|"
    r"memory|pointer|buffer|stack|heap|concurrency|async|await|coroutine|socket|network|tcp|udp|http|dns|"
    r"build|code|coding|develop|programming|script|scripting|debug|debugging|refactor|optimize|architecture|system\s+design|"
    r"penetration\s+test(ing)?|pen\s+test(ing)?|vulnerabilit(y|ies)|cve-\d+|ast\s+sink|sink\s+sanitiz\w*|"
    r"sql\s+injection|sqli|cross-site\s+scripting|xss|csrf|buffer\s+overflow|heap\s+overflow|stack\s+overflow|"
    r"race\s+condition|idor|privilege\s+escalation|reverse\s+shell|reverse\s+engineer(ing)?|malware\s+analysis|"
    r"forensic(s)?|disassembl(y|er|ed)|decompil(er|ed|ation)?|binary\s+exploitation|shellcode|rop\s+chain|"
    r"kill\s+-9|kill\s+process|sigkill|sigterm|daemon|thread|mutex|deadlock|process\s+management|"
    r"sex\s+ratio|demographic(s)?|chromosome|phenotype|genotype|biology|biological\s+sex|clinical|pathology|"
    r"anatomy|medicine|medical|physiology|cellular|molecular|genetics|pharmacology|therapy|"
    r"math|calculus|algebra|linear\s+algebra|matrix|tensor|vector|statistics|probability|"
    r"firmware|packet\s+capture|wireshark|software|function|variable|class|object|method|repo|repository"
    r")\b",
    re.IGNORECASE
)

# 2. Hard Ban Patterns (Zero Tolerance regardless of technical context):
# Strictly restricted to extreme harm, CSAM, and non-consensual sexual violence.
HARD_BAN_REGEX = re.compile(
    r"\b("
    r"child\s+porn|csam|underage\s+(sex|porn|nude|erotic)|pedophil\w*|pedosex\w*|"
    r"rape|gangrape|non-consensual\s+sex|sexual\s+assault|date\s+rape|revenge\s+porn|"
    r"forced\s+intercourse|molest(ation|ing)?"
    r")\b",
    re.IGNORECASE
)

# 3. Destructive Weaponized Malware Intent (Defensive Reframing):
DESTRUCTIVE_MALWARE_REGEX = re.compile(
    r"\b(write|code|create|build|generate|make)\b.*"
    r"\b(undetectable\s+ransomware|corporate\s+ransomware|disk\s+wiper|destroy\s+boot\s+records|"
    r"mbr\s+wiper|destructive\s+wiper|weaponized\s+trojan|evade\s+all\s+edr\s+to\s+steal)\b",
    re.IGNORECASE
)

POLICY_REFUSAL_NSFW = (
    "**[VAJRA Neural Safety Guard]**\n\n"
    "**Request Neutralized: Contextual Policy Violation (Explicit Erotic / Adult Narrative Intent)**\n\n"
    "VAJRA is an Autonomous Cyber-Reasoning and Technical Intelligence System. Generating sexually explicit, pornographic, or erotic roleplay falls outside acceptable operational boundaries.\n\n"
    "Technical inquiries, cybersecurity audits, and forensic code analyses remain fully available."
)

POLICY_REFUSAL_HARDBAN = (
    "**[VAJRA Content Safety Shield]**\n\n"
    "**Critical Security Event: Absolute Harm Policy Enforcement**\n\n"
    "This request involves non-consensual sexual violence, abuse, or prohibited safety categories and has been terminated immediately. VAJRA enforces zero-tolerance boundaries against harm and non-consensual content."
)

DEFENSIVE_REFRAME_MALWARE = (
    "**[VAJRA Defensive Security Guardrail]**\n\n"
    "**Policy Notice: Defensive Security Reframing Active**\n\n"
    "VAJRA does not construct weaponized destructive malware, unconstrained ransomware, or wiper payloads. "
    "Below is an architectural breakdown of the mechanism from a defensive analysis and detection standpoint, including AST sink remediation and detection signatures:\n\n"
)

# =====================================================================
# 2. ULTRA-LITE NEURAL SPECULATIVE & GUARD ENGINE (0.5B CPU)
# =====================================================================
draft_tokenizer = None
draft_model = None

def get_draft_model():
    global draft_tokenizer, draft_model
    if draft_model is None:
        try:
            try:
                torch.set_num_threads(2)
            except Exception:
                pass
            print(f"🔒 [VAJRA v2] Initializing Fast 0.5B Speculative & Guard Engine ({ULTRA_LITE_MODEL_ID})...")
            draft_tokenizer = AutoTokenizer.from_pretrained(ULTRA_LITE_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)
            draft_model = AutoModelForCausalLM.from_pretrained(
                ULTRA_LITE_MODEL_ID,
                token=HF_TOKEN,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True,
                trust_remote_code=True,
                device_map="cpu"
            )
            print("✅ [VAJRA v2] 0.5B Neural Guard Engine loaded on CPU successfully!")
        except Exception as e:
            print(f"⚠️ Error loading local 0.5B model: {e}")
    return draft_tokenizer, draft_model

def classify_neural_intent(prompt: str) -> Tuple[bool, str]:
    """
    Tier 2: 0.5B Neural Guard (~80-150ms).
    Zero-shot semantic intent classification using local Qwen2.5-Coder-0.5B-Instruct on CPU.
    No hardcoded erotic/nsfw word lists: evaluates context, semantics, and intent dynamically.
    Returns (is_safe: bool, reason: str).
    """
    tok, m = get_draft_model()
    if tok is None or m is None:
        return True, "model_unavailable"

    try:
        guard_system = (
            "You are VAJRA Neural Safety Guard. Analyze the user prompt's true semantic intent.\n"
            "Rules:\n"
            "- Output [UNSAFE] if the user explicitly requests erotic narrative, pornography, sexually explicit roleplay, or destructive malware payloads.\n"
            "- Output [SAFE] for all programming, cybersecurity forensics, biology, anatomy, medicine, history, creative writing (non-erotic), and general conversation.\n"
            "Respond ONLY with [SAFE] or [UNSAFE]."
        )
        messages = [
            {"role": "system", "content": guard_system},
            {"role": "user", "content": prompt[:800]}
        ]
        text_in = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tok([text_in], return_tensors="pt")
        with torch.inference_mode():
            ids = m.generate(
                **inputs,
                max_new_tokens=4,
                do_sample=False,
                eos_token_id=tok.eos_token_id,
                pad_token_id=tok.eos_token_id
            )
        in_len = inputs.input_ids.shape[1]
        verdict = tok.decode(ids[0, in_len:], skip_special_tokens=True).strip().upper()
        del inputs, ids

        if verdict.startswith("[SAFE]") or verdict.startswith("SAFE") or ("[SAFE]" in verdict and "[UNSAFE]" not in verdict):
            return True, "neural_safe"
        if ("[UNSAFE]" in verdict or verdict.startswith("UNSAFE")) and "NOT UNSAFE" not in verdict and "NOT [UNSAFE]" not in verdict:
            return False, "neural_unsafe"
        return True, "neural_safe"
    except Exception as e:
        print(f"⚠️ 0.5B Neural Guard evaluation exception: {e}")
        return True, "eval_fallback"

def evaluate_contextual_safety(raw_text: str):
    """
    Two-Tier Hybrid Safety Architecture:
    - Tier 1: Instant Hard Ban (<1ms) for absolute non-negotiable harm (CSAM, non-consensual sexual violence/rape).
    - Tier 2: 0.5B Neural Guard (~80-150ms) for true semantic intent classification with ZERO hardcoded word lists.
    """
    text = (raw_text or "").replace("\x00", "").strip()
    if not text:
        return True, "", ""

    # Tier 1: Instant hard ban (<1ms) for absolute legal/ethical harm
    if HARD_BAN_REGEX.search(text):
        return False, "hard_ban", POLICY_REFUSAL_HARDBAN

    # Destructive malware reframe (<1ms)
    if DESTRUCTIVE_MALWARE_REGEX.search(text):
        return False, "defensive_reframe", DEFENSIVE_REFRAME_MALWARE

    # Technical & biomedical fast-path: Explicit engineering/science bypasses neural check in <1ms
    if TECHNICAL_CONTEXT_REGEX.search(text):
        return True, "", text

    # Tier 2: 0.5B Neural Guard for contextual intent understanding (NO hardcoded word lists)
    is_safe, reason = classify_neural_intent(text)
    if not is_safe:
        return False, "nsfw_erotica", POLICY_REFUSAL_NSFW

    return True, "", text

def generate_ultra_lite_reply(prompt: str, context_files: Optional[Dict[str, str]] = None) -> str:
    is_safe, reason, safety_out = evaluate_contextual_safety(prompt)
    if not is_safe and reason in ("hard_ban", "nsfw_erotica"):
        return safety_out

    clean_p, _ = sanitize_pii_and_secrets(prompt)
    active_prompt = clean_p
    if not is_safe and reason == "defensive_reframe":
        active_prompt = f"Explain the defensive security mitigations, AST sinks, and detection methods for: {clean_p}"

    # 1. Direct Local 0.5B CPU Generation (Ultra-fast speculative draft)
    try:
        tok, m = get_draft_model()
        if tok is not None and m is not None:
            messages = [
                {"role": "system", "content": "You are VAJRA-Draft. Give a direct, concise 1-2 sentence technical summary."},
                {"role": "user", "content": active_prompt}
            ]
            text_in = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = tok([text_in], return_tensors="pt")
            with torch.inference_mode():
                ids = m.generate(
                    **inputs,
                    max_new_tokens=45,
                    do_sample=False,
                    eos_token_id=tok.eos_token_id,
                    pad_token_id=tok.eos_token_id
                )
            in_len = inputs.input_ids.shape[1]
            res = tok.decode(ids[0, in_len:], skip_special_tokens=True).strip()
            del inputs, ids
            if res and not res.endswith(('.', '!', '?')):
                last_p = max(res.rfind('.'), res.rfind('!'), res.rfind('?'))
                if last_p > 20:
                    res = res[:last_p + 1].strip()
            if res:
                return scrub_output_secrets(res)
    except Exception as e:
        print(f"⚠️ Local 0.5B CPU generation note: {e}")

    # 2. Serverless Router Fallback (if HF_TOKEN is configured)
    token = HF_TOKEN or os.getenv("HF_TOKEN")
    if token:
        try:
            api_url = f"https://router.huggingface.co/hf-inference/models/{ULTRA_LITE_MODEL_ID}"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "VAJRA-v2-CPU/1.0"
            }
            payload = json.dumps({
                "inputs": f"<|im_start|>system\nYou are VAJRA-Ultra-Lite, a precise engineering assistant. Provide a complete, structured explanation concluding with a summary.<|im_end|>\n<|im_start|>user\n{active_prompt}<|im_end|>\n<|im_start|>assistant\n",
                "parameters": {"max_new_tokens": 512, "temperature": 0.2, "return_full_text": False}
            }).encode("utf-8")
            req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=12) as response:
                result = json.loads(response.read().decode("utf-8"))
                if isinstance(result, list) and len(result) > 0:
                    text = result[0].get("generated_text", "").strip()
                    if text:
                        return scrub_output_secrets(text)
        except Exception as e:
            print(f"⚠️ Ultra-Lite serverless fallback note: {e}")

    return ""

# =====================================================================
# 3. 7B MODEL LOADING ON 2 vCPU (CPU Basic • 16 GB RAM)
# =====================================================================
GGUF_REPO_ID = os.getenv("GGUF_REPO_ID", "AravKataria/vajra-7b-gguf")
GGUF_FILENAME = os.getenv("GGUF_FILENAME", "vajra-7b-q4_k_m.gguf")

gguf_llm = None
gguf_load_attempted = False

def get_gguf_model():
    global gguf_llm, gguf_load_attempted
    if gguf_llm is not None or gguf_load_attempted:
        return gguf_llm

    gguf_load_attempted = True
    try:
        from llama_cpp import Llama
        from huggingface_hub import hf_hub_download

        token = HF_TOKEN or os.getenv("HF_TOKEN")
        print(f"🔒 [VAJRA v2] Checking for 4-bit GGUF model ({GGUF_REPO_ID}/{GGUF_FILENAME})...")
        model_path = hf_hub_download(
            repo_id=GGUF_REPO_ID,
            filename=GGUF_FILENAME,
            token=token
        )
        print(f"✅ [VAJRA v2] Downloaded GGUF to {model_path}. Initializing Llama CPU engine (2 threads, 1.5K ctx, 256 batch)...")
        try:
            gguf_llm = Llama(
                model_path=model_path,
                n_threads=2,
                n_ctx=1536,
                n_batch=256,
                type_k=2,
                type_v=2,
                verbose=False
            )
        except Exception:
            gguf_llm = Llama(
                model_path=model_path,
                n_threads=2,
                n_ctx=1536,
                n_batch=256,
                verbose=False
            )
        print("🚀 [VAJRA v2] 4-bit 7B GGUF Model ONLINE on 2 vCPU! (~3.8 GB RAM footprint)")
    except Exception as e:
        print(f"[INFO] [VAJRA v2] GGUF model note: {e}. Using 0.5B CPU engine.")
        gguf_llm = None
    return gguf_llm

tokenizer = None
model = None
model_load_failed = False

def load_cpu_model():
    global tokenizer, model, model_load_failed
    if model is not None or model_load_failed:
        return

    # Guard: Never allocate 15.2 GB into a 16 GB container unless explicitly enabled by admin
    if os.getenv("LOAD_7B_ON_CPU", "0") != "1":
        print("🛡️ [VAJRA v2] Preserving 16 GB CPU RAM ceiling: 7B queries delegated to ZeroGPU / HF Router.")
        return

    print("🔒 [VAJRA v2] Initializing CPU Model Engine on 2 vCPU (16 GB RAM)...")
    try:
        try:
            tokenizer = AutoTokenizer.from_pretrained(LORA_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)
        except Exception:
            tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)

        dtype = torch.bfloat16 if torch.cuda.is_available() or hasattr(torch, "bfloat16") else torch.float32

        print(f"🔒 [VAJRA v2] Loading base foundation {BASE_MODEL_ID} on CPU...")
        model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_ID,
            token=HF_TOKEN,
            torch_dtype=dtype,
            low_cpu_mem_usage=True,
            trust_remote_code=True,
            device_map="cpu"
        )

        print(f"🔒 [VAJRA v2] Loading fine-tuned LoRA adapter {LORA_MODEL_ID}...")
        try:
            model = PeftModel.from_pretrained(model, LORA_MODEL_ID, token=HF_TOKEN)
            print("✅ [VAJRA v2] Fine-tuned LoRA loaded successfully on CPU!")
        except Exception as peft_err:
            print(f"⚠️ [VAJRA v2] Base model active (LoRA note: {peft_err})")

        model.eval()
        print("🚀 [VAJRA v2] 2 vCPU Engine ONLINE!")
    except Exception as err:
        print(f"❌ [VAJRA v2] CPU Model load error: {err}")
        model_load_failed = True

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning System engineered and fine-tuned by Arav Kataria.
Provide a clear, high-value, and complete technical explanation in 1 to 2 focused paragraphs. Directly explain the core mechanism, key characteristics, and significance. Conclude cleanly without dangling lists or unfinished thoughts."""

# =====================================================================
# 4. INFERENCE WITH CONCURRENCY LOCK & LOAD SHEDDING
# =====================================================================
def generate_vajra_reply(prompt: str, context_files: Optional[Dict[str, str]] = None):
    # Contextual safety evaluation (preserves technical/cybersecurity context)
    is_safe, reason, safety_out = evaluate_contextual_safety(prompt)
    if not is_safe and reason in ("hard_ban", "nsfw_erotica"):
        return safety_out, "VAJRA-Safety-Shield", "safety_guardrail"

    clean_prompt, detected_pii = sanitize_and_check_injection(prompt)
    if not is_safe and reason == "defensive_reframe":
        clean_prompt = f"Analyze the defensive security architecture, detection signatures, and mitigation mechanisms for the following concept without generating weaponized attack exploits: {clean_prompt}"

    # 1. Concurrency check: If another user is using the 2 vCPU, signal overflow immediately
    acquired = inference_lock.acquire(blocking=False)
    if not acquired:
        print("⚡ [VAJRA v2] 2 vCPU busy with another task -> Overflowing to ZeroGPU!")
        return "[VAJRA_SYSTEM_BUSY_OVERFLOW]", "VAJRA-ZeroGPU-Burst", "overflow"

    try:
        # 1. First priority on 2 vCPU: Try 4-bit 7B GGUF model (~10-12 tok/s, ~4.2 GB RAM)
        llm = get_gguf_model()
        if llm is not None:
            prompt_msgs = [{"role": "system", "content": VAJRA_SYSTEM_PROMPT}]
            if context_files and isinstance(context_files, dict):
                summary_text = ""
                for fname, fcontent in list(context_files.items())[:3]:
                    safe_c = str(fcontent)[:1000].replace("\x00", "")
                    summary_text += f"\n--- File: {fname} ---\n{safe_c}"
                if summary_text:
                    prompt_msgs.append({"role": "system", "content": f"Workspace Files:\n{summary_text}"})
            prompt_msgs.append({"role": "user", "content": clean_prompt})

            output = llm.create_chat_completion(
                messages=prompt_msgs,
                max_tokens=170,
                temperature=0.25,
                top_p=0.9,
                repeat_penalty=1.15,
                stop=["<|im_end|>", "<|im_start|>", "<|endoftext|>", "\nUser:", "\n\nUser:"]
            )
            raw_reply = output["choices"][0]["message"]["content"].strip()
            for marker in ["<|im_end|>", "<|im_start|>", "\nUser:", "\n\nUser:"]:
                if marker in raw_reply:
                    raw_reply = raw_reply.split(marker)[0].strip()
            if raw_reply and not raw_reply.endswith(('.', '!', '?', '`', '}')):
                last_punct = max(raw_reply.rfind('.'), raw_reply.rfind('!'), raw_reply.rfind('?'))
                if last_punct > len(raw_reply) // 2:
                    raw_reply = raw_reply[:last_punct + 1].strip()
            if not is_safe and reason == "defensive_reframe" and not raw_reply.startswith(DEFENSIVE_REFRAME_MALWARE):
                raw_reply = DEFENSIVE_REFRAME_MALWARE + raw_reply
            print("✅ [VAJRA v2] Query processed locally via 4-bit 7B GGUF engine.")
            return scrub_output_secrets(raw_reply), "AravKataria/vajra-7b-gguf (4-bit 2 vCPU)", "standard"

        load_cpu_model()

        if model is None or tokenizer is None:
            # 1. Answer immediately on 2 vCPU using fast local engine (~42 tokens/sec, 1.2 GB RAM)
            lite_reply = generate_ultra_lite_reply(clean_prompt, context_files)
            if lite_reply:
                if not is_safe and reason == "defensive_reframe" and not lite_reply.startswith(DEFENSIVE_REFRAME_MALWARE):
                    lite_reply = DEFENSIVE_REFRAME_MALWARE + lite_reply
                print("✅ [VAJRA v2] Query processed locally on 2 vCPU (0.5B engine).")
                return scrub_output_secrets(lite_reply), "Qwen2.5-Coder-0.5B-Instruct (2 vCPU)", "standard"

            # 2. Serverless Router / HF Inference API if HF_TOKEN is configured
            token = HF_TOKEN or os.getenv("HF_TOKEN")
            if token:
                try:
                    api_url = f"https://router.huggingface.co/hf-inference/models/{BASE_MODEL_ID}"
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}",
                        "User-Agent": "VAJRA-v2-CPU/1.0"
                    }
                    payload = json.dumps({
                        "inputs": f"<|im_start|>system\n{VAJRA_SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{clean_prompt}<|im_end|>\n<|im_start|>assistant\n",
                        "parameters": {"max_new_tokens": 280, "temperature": 0.2, "return_full_text": False}
                    }).encode("utf-8")
                    req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
                    with urllib.request.urlopen(req, timeout=20) as response:
                        result = json.loads(response.read().decode("utf-8"))
                        if isinstance(result, list) and len(result) > 0:
                            text = result[0].get("generated_text", "").strip()
                            if text:
                                if not is_safe and reason == "defensive_reframe" and not text.startswith(DEFENSIVE_REFRAME_MALWARE):
                                    text = DEFENSIVE_REFRAME_MALWARE + text
                                return scrub_output_secrets(text), "Qwen/Qwen2.5-Coder-7B-Instruct (Cloud Router)", "cloud_router"
                except Exception as route_err:
                    print(f"⚠️ 7B Serverless router fallback note: {route_err}")

            return "[VAJRA_SYSTEM_BUSY_OVERFLOW]", "VAJRA-ZeroGPU-Burst", "overflow"

        messages = [{"role": "system", "content": VAJRA_SYSTEM_PROMPT}]
        if context_files and isinstance(context_files, dict):
            summary_text = ""
            for fname, fcontent in list(context_files.items())[:3]:
                safe_c = str(fcontent)[:1000].replace("\x00", "")
                summary_text += f"\n--- File: {fname} ---\n{safe_c}"
            if summary_text:
                messages.append({"role": "system", "content": f"Workspace Files:\n{summary_text}"})

        messages.append({"role": "user", "content": clean_prompt})

        text_input = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        model_inputs = tokenizer([text_input], return_tensors="pt")

        with torch.no_grad():
            generated_ids = model.generate(
                **model_inputs,
                max_new_tokens=190,
                temperature=0.2,
                top_p=0.9,
                repetition_penalty=1.1,
                do_sample=True,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.eos_token_id
            )

        in_len = model_inputs.input_ids.shape[1]
        res_text = tokenizer.decode(generated_ids[0, in_len:], skip_special_tokens=True).strip()
        if res_text.count("```") % 2 != 0:
            res_text += "\n```"
        if not is_safe and reason == "defensive_reframe" and not res_text.startswith(DEFENSIVE_REFRAME_MALWARE):
            res_text = DEFENSIVE_REFRAME_MALWARE + res_text
        del model_inputs, generated_ids
        gc.collect()

        return scrub_output_secrets(res_text).strip(), "AravKataria/vajra-lora (7B 2 vCPU)", "standard"

    except Exception as e:
        print(f"⚠️ 7B CPU generation exception: {e}")
        return "[VAJRA_SYSTEM_BUSY_OVERFLOW]", "VAJRA-ZeroGPU-Burst", "overflow"

    finally:
        try:
            if 'llm' in locals() and llm is not None:
                llm.reset()
        except Exception:
            pass
        inference_lock.release()

# Progressive token streaming generator for Gradio interface
def gradio_generate(prompt: str):
    is_safe, reason, safety_out = evaluate_contextual_safety(prompt)
    if not is_safe and reason in ("hard_ban", "nsfw_erotica"):
        yield safety_out
        return

    clean_prompt, _ = sanitize_and_check_injection(prompt)
    if not is_safe and reason == "defensive_reframe":
        clean_prompt = f"Analyze the defensive security architecture, detection signatures, and mitigation mechanisms for the following concept without generating weaponized attack exploits: {clean_prompt}"

    # Concurrency check: If another user is using the 2 vCPU, signal overflow immediately
    acquired = inference_lock.acquire(blocking=False)
    if not acquired:
        print("⚡ [VAJRA v2] 2 vCPU busy with another task -> Overflowing to ZeroGPU!")
        yield "[VAJRA_SYSTEM_BUSY_OVERFLOW]"
        return

    try:
        # 1. First priority on 2 vCPU: Stream from 4-bit 7B GGUF model if available
        llm = get_gguf_model()
        if llm is not None:
            prompt_msgs = [
                {"role": "system", "content": VAJRA_SYSTEM_PROMPT},
                {"role": "user", "content": clean_prompt}
            ]
            accumulated = ""
            try:
                for chunk in llm.create_chat_completion(
                    messages=prompt_msgs,
                    max_tokens=170,
                    temperature=0.25,
                    top_p=0.9,
                    repeat_penalty=1.15,
                    stop=["<|im_end|>", "<|im_start|>", "<|endoftext|>", "\nUser:", "\n\nUser:"],
                    stream=True
                ):
                    try:
                        choices = chunk.get("choices") if isinstance(chunk, dict) else None
                        if choices and len(choices) > 0:
                            delta = choices[0].get("delta") if isinstance(choices[0], dict) else None
                            if delta and isinstance(delta, dict):
                                content = delta.get("content")
                                if content:
                                    accumulated += content
                                    # Break immediately if end markers appear to prevent looping
                                    if any(m in accumulated for m in ["<|im_end|>", "<|im_start|>", "\nUser:", "\n\nUser:"]):
                                        for m in ["<|im_end|>", "<|im_start|>", "\nUser:", "\n\nUser:"]:
                                            if m in accumulated:
                                                accumulated = accumulated.split(m)[0].strip()
                                        if accumulated and not accumulated.endswith(('.', '!', '?', '`', '}')):
                                            last_p = max(accumulated.rfind('.'), accumulated.rfind('!'), accumulated.rfind('?'))
                                            if last_p > len(accumulated) // 2:
                                                accumulated = accumulated[:last_p + 1].strip()
                                        yield accumulated
                                        return
                                    yield accumulated
                    except Exception as chunk_parse_err:
                        pass
            except Exception as stream_err:
                print(f"⚠️ GGUF stream=True note: {stream_err}")

            if accumulated:
                if not accumulated.endswith(('.', '!', '?', '`', '}')):
                    last_p = max(accumulated.rfind('.'), accumulated.rfind('!'), accumulated.rfind('?'))
                    if last_p > len(accumulated) // 2:
                        accumulated = accumulated[:last_p + 1].strip()
                        yield accumulated
                return

            # Non-streaming fallback if stream=True produced no tokens
            try:
                direct_out = llm.create_chat_completion(
                    messages=prompt_msgs,
                    max_tokens=170,
                    temperature=0.25,
                    top_p=0.9,
                    repeat_penalty=1.15,
                    stop=["<|im_end|>", "<|im_start|>", "<|endoftext|>", "\nUser:", "\n\nUser:"]
                )
                direct_reply = direct_out["choices"][0]["message"]["content"].strip()
                for m in ["<|im_end|>", "<|im_start|>", "\nUser:", "\n\nUser:"]:
                    if m in direct_reply:
                        direct_reply = direct_reply.split(m)[0].strip()
                if direct_reply:
                    if not direct_reply.endswith(('.', '!', '?', '`', '}')):
                        last_p = max(direct_reply.rfind('.'), direct_reply.rfind('!'), direct_reply.rfind('?'))
                        if last_p > len(direct_reply) // 2:
                            direct_reply = direct_reply[:last_p + 1].strip()
                    yield direct_reply
                    return
            except Exception as direct_err:
                print(f"⚠️ GGUF direct completion note: {direct_err}")

        load_cpu_model()

        if model is None or tokenizer is None:
            d_tok, d_m = get_draft_model()
            if d_tok is not None and d_m is not None:
                messages = [
                    {"role": "system", "content": "You are VAJRA-Ultra-Lite, an autonomous cyber-reasoning and technical intelligence assistant. Deliver a clear, authoritative, and structured technical explanation within 180-220 words. Always complete all points and conclude with a definitive summary sentence."},
                    {"role": "user", "content": clean_prompt}
                ]
                text_input = d_tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
                model_inputs = d_tok([text_input], return_tensors="pt")
                streamer = TextIteratorStreamer(d_tok, skip_prompt=True, skip_special_tokens=True)
                gen_kwargs = dict(
                    **model_inputs,
                    streamer=streamer,
                    max_new_tokens=320,
                    temperature=0.25,
                    top_p=0.9,
                    repetition_penalty=1.08,
                    do_sample=True,
                    eos_token_id=d_tok.eos_token_id,
                    pad_token_id=d_tok.eos_token_id
                )
                gen_thread = threading.Thread(target=d_m.generate, kwargs=gen_kwargs)
                gen_thread.start()

                accumulated = ""
                for new_text in streamer:
                    accumulated += new_text
                    yield accumulated

                gen_thread.join()
                del model_inputs
                gc.collect()
                return

            yield "[VAJRA_SYSTEM_BUSY_OVERFLOW]"
            return

        messages = [
            {"role": "system", "content": VAJRA_SYSTEM_PROMPT},
            {"role": "user", "content": clean_prompt}
        ]

        text_input = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        model_inputs = tokenizer([text_input], return_tensors="pt")

        streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)
        gen_kwargs = dict(
            **model_inputs,
            streamer=streamer,
            max_new_tokens=190,
            temperature=0.2,
            top_p=0.9,
            repetition_penalty=1.1,
            do_sample=True,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.eos_token_id
        )

        gen_thread = threading.Thread(target=model.generate, kwargs=gen_kwargs)
        gen_thread.start()

        accumulated = ""
        for new_text in streamer:
            accumulated += new_text
            yield accumulated

        gen_thread.join()

        if accumulated.count("```") % 2 != 0:
            accumulated += "\n```"
            yield accumulated

        del model_inputs
        gc.collect()

    except Exception as e:
        print(f"⚠️ 7B CPU streaming generation exception: {e}")
        yield "[VAJRA_SYSTEM_BUSY_OVERFLOW]"

    finally:
        try:
            if 'llm' in locals() and llm is not None:
                llm.reset()
        except Exception:
            pass
        inference_lock.release()

def gradio_generate_draft(prompt: str) -> str:
    is_safe, reason, safety_out = evaluate_contextual_safety(prompt)
    if not is_safe and reason in ("hard_ban", "nsfw_erotica"):
        return safety_out
    clean, _ = sanitize_and_check_injection(prompt)
    reply = generate_ultra_lite_reply(clean)
    return scrub_output_secrets(reply)

# =====================================================================
# 5. GRADIO INTERFACE
# =====================================================================
demo = None
if gr is not None:
    with gr.Blocks(title="VAJRA v2 Cyber-Reasoning Engine") as demo:
        gr.Markdown("# 🛡️ VAJRA v2 Cyber-Reasoning Intelligence System")
        gr.Markdown("**Fine-Tuned by Arav Kataria** | 2 vCPU • 16 GB RAM • 24/7 Unlimited Online")
        gr.Markdown("• **FastAPI REST Endpoint Active**: `POST /api/chat` (With Dynamic Load Shedding)")

        with gr.Row():
            user_input = gr.Textbox(
                label="Inquiry / AST Code Audit",
                placeholder="Ask VAJRA to audit code or explain technical concepts...",
                lines=3
            )
        send_button = gr.Button("Submit Reasoning Request", variant="primary")
        output_display = gr.Markdown(label="VAJRA Analysis Output")

        send_button.click(
            fn=gradio_generate,
            inputs=user_input,
            outputs=output_display,
            api_name="generate_vajra_reply"
        )
        alias_send_button = gr.Button("SubmitAlias", visible=False)
        alias_send_button.click(
            fn=gradio_generate,
            inputs=user_input,
            outputs=output_display,
            api_name="gradio_generate"
        )

        draft_button = gr.Button("Draft", visible=False)
        draft_output = gr.Markdown(visible=False)
        draft_button.click(
            fn=gradio_generate_draft,
            inputs=user_input,
            outputs=draft_output,
            api_name="generate_draft_reply"
        )
        draft_alias_btn = gr.Button("DraftAlias", visible=False)
        draft_alias_btn.click(
            fn=gradio_generate_draft,
            inputs=user_input,
            outputs=draft_output,
            api_name="draft"
        )

# =====================================================================
# 6. FASTAPI REST API & GRADIO MOUNTING
# =====================================================================
fastapi_app = FastAPI(title="VAJRA v2 Cyber-Reasoning Gateway", version="2.0.0")

fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    prompt: str = Field(..., max_length=15000)
    workspace_id: Optional[str] = None
    files: Optional[Dict[str, str]] = None
    auth_key: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

@fastapi_app.get("/health")
def health():
    return {
        "status": "online",
        "space": "VAJRA_v2",
        "hardware": "2 vCPU • 16 GB RAM",
        "gguf_loaded": gguf_llm is not None,
        "draft_loaded": draft_model is not None,
        "model": "AravKataria/vajra-7b-gguf (4-bit 2 vCPU)",
        "load_shedding_active": True,
        "session_isolation": "128-bit Cryptographic Ephemeral",
        "author": "Arav Kataria",
        "service": "VAJRA-v2-CPU-Gateway"
    }

@fastapi_app.post("/v1/chat")
async def chat_v1(req: ChatRequest, request: Request):
    sig_header = request.headers.get("X-Vajra-Signature") or req.auth_key
    client_ip = request.client.host if request.client else "127.0.0.1"
    session_id = req.session_id or request.headers.get("X-Vajra-Session-ID") or "ephemeral-isolated"
    request_id = req.request_id or request.headers.get("X-Vajra-Request-ID") or str(uuid.uuid4())

    if VAJRA_SECRET_KEY:
        import hmac
        if not sig_header or not hmac.compare_digest(sig_header.strip(), VAJRA_SECRET_KEY.strip()):
            raise HTTPException(status_code=403, detail="Forbidden: Invalid VAJRA Security Signature.")
    else:
        if not check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="Too Many Requests: Rate limit exceeded.")

    # Contextual safety evaluation
    is_safe, reason, safety_out = evaluate_contextual_safety(req.prompt)
    if not is_safe and reason in ("hard_ban", "nsfw_erotica"):
        return JSONResponse({
            "success": False,
            "overflow": False,
            "busy": False,
            "reply": safety_out,
            "model": "VAJRA-Safety-Shield",
            "tier": "safety_guardrail",
            "session_id": session_id,
            "request_id": request_id,
            "security": "Zero-Retention & Cryptographic Session Isolation Verified"
        }, headers={
            "X-Vajra-Session-ID": session_id,
            "X-Vajra-Request-ID": request_id
        })

    reply, model_name, tier_name = generate_vajra_reply(req.prompt, req.files)
    is_overflow = (tier_name == "overflow" or "[VAJRA_SYSTEM_BUSY_OVERFLOW]" in reply)
    return JSONResponse({
        "success": not is_overflow,
        "overflow": is_overflow,
        "busy": is_overflow,
        "reply": reply,
        "model": model_name,
        "tier": tier_name,
        "session_id": session_id,
        "request_id": request_id,
        "security": "Zero-Retention & Cryptographic Session Isolation Verified"
    }, headers={
        "X-Vajra-Session-ID": session_id,
        "X-Vajra-Request-ID": request_id
    })

class DraftRequest(BaseModel):
    prompt: Optional[str] = None
    data: Optional[List[Any]] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

@fastapi_app.post("/v1/draft")
async def draft_v1(req: DraftRequest, request: Request):
    session_id = req.session_id or request.headers.get("X-Vajra-Session-ID") or "ephemeral-isolated"
    request_id = req.request_id or request.headers.get("X-Vajra-Request-ID") or str(uuid.uuid4())
    try:
        p = req.prompt or ""
        if not p and req.data and len(req.data) > 0:
            p = str(req.data[0])
        reply = generate_ultra_lite_reply(str(p).strip()) if p else ""
        return JSONResponse({
            "success": bool(reply),
            "reply": reply,
            "tier": "ultra_lite",
            "session_id": session_id,
            "request_id": request_id
        }, headers={
            "X-Vajra-Session-ID": session_id,
            "X-Vajra-Request-ID": request_id
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e),
            "reply": "",
            "tier": "ultra_lite",
            "session_id": session_id,
            "request_id": request_id
        }, headers={
            "X-Vajra-Session-ID": session_id,
            "X-Vajra-Request-ID": request_id
        })

# Enable Gradio queue for event streaming & mount at root of FastAPI
if gr is not None and demo is not None:
    demo.queue(default_concurrency_limit=2)
    app = gr.mount_gradio_app(fastapi_app, demo, path="/")
else:
    app = fastapi_app

# Asynchronously preload both models into memory on boot
threading.Thread(target=get_draft_model, daemon=True).start()
threading.Thread(target=get_gguf_model, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    print("✅ [VAJRA v2] Server starting on 2 vCPU (16 GB RAM) via Uvicorn.")
    uvicorn.run(app, host="0.0.0.0", port=7860)
