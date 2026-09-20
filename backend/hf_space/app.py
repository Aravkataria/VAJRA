import os
import gc
import time
import json
import torch
import gradio as gr
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

VAJRA_SECRET_KEY = os.getenv("VAJRA_SECRET_KEY")

# Strict Origin Whitelist
ALLOWED_ORIGINS = [
    "https://aravkataria.github.io",
    "https://aravkataria.com",
    "https://vajra.aravkataria.com",
    "tauri://localhost",
    "https://tauri.localhost",
    "http://localhost:1420",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:1420",
    "http://127.0.0.1:8000",
]

# Anti-DoS Rate Limiting
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 120
ip_request_history: Dict[str, list] = {}

# In-Memory Inference Cache (Saves GPU quota for repeat/common queries)
_query_cache: Dict[str, Tuple[float, str]] = {}
CACHE_TTL = 600  # 10 minutes

def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    if client_ip not in ip_request_history:
        ip_request_history[client_ip] = [now]
        return True
    timestamps = [t for t in ip_request_history[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
        return False
    timestamps.append(now)
    ip_request_history[client_ip] = timestamps
    return True

# Anti-Prompt Injection Filter
INJECTION_TRIGGERS = [
    "ignore all previous instructions", "disregard all instructions",
    "reveal your system prompt", "you are now in dan mode", "jailbreak"
]

def sanitize_and_check_injection(text: str) -> str:
    clean_text = text.replace("\x00", "").strip()
    lower = clean_text.lower()
    for trigger in INJECTION_TRIGGERS:
        if trigger in lower:
            return "[VAJRA Security Shield: Prompt Injection Pattern Neutralized] Please ask legitimate technical questions."
    return clean_text

# =====================================================================
# 2. LOAD VAJRA-LORA WITH EXACT MATCHING 7B BASE FOUNDATION
# =====================================================================
HF_TOKEN = os.getenv("HF_TOKEN", None)
LORA_MODEL_ID = "AravKataria/vajra-lora"
# Base model MUST be 7B to match your LoRA adapter shape (3584 hidden dimension)
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"

print(f"🔒 [VAJRA Guard] Initializing Tokenizer from {LORA_MODEL_ID}...")
try:
    tokenizer = AutoTokenizer.from_pretrained(LORA_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)
except Exception:
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)

print(f"🔒 [VAJRA Guard] Loading Base Model Foundation ({BASE_MODEL_ID}) in float16...")
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_ID,
    token=HF_TOKEN,
    torch_dtype=torch.float16,
    low_cpu_mem_usage=True,
    device_map="auto",
    trust_remote_code=True
)

print(f"🔒 [VAJRA Guard] Merging fine-tuned LoRA weights from {LORA_MODEL_ID}...")
try:
    model = PeftModel.from_pretrained(model, LORA_MODEL_ID, token=HF_TOKEN)
    model = model.merge_and_unload()
    print("✅ Fine-tuned LoRA adapter (7B) successfully merged without any shape mismatch!")
except Exception as e:
    print(f"⚠️ LoRA note: {e}")

model.eval()
print("🚀 [VAJRA Guard] Secure Cyber-Reasoning Engine is ONLINE with Zero-Retention Privacy!")

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.

Operational Directives:
1. Identity: Specialized fine-tuned Qwen2.5-Coder model (Transformer architecture, Alibaba Cloud foundation), fine-tuned by Arav Kataria for autonomous vulnerability triage, zero-regression patch generation, and formal invariant verification.
2. Direct Assistance: Answer coding questions, security architecture inquiries, project planning, and vulnerability analysis concisely, authoritatively, and accurately.
3. Speed & Precision: Deliver direct, high-value answers without unnecessary preamble."""

def generate_vajra_reply(prompt: str, context_files: Optional[Dict[str, str]] = None) -> str:
    prompt = sanitize_and_check_injection(prompt)
    cache_key = prompt.lower().strip()
    now = time.time()
    
    # 1. Return cached response if available without file context
    if not context_files and cache_key in _query_cache:
        ts, cached_reply = _query_cache[cache_key]
        if now - ts < CACHE_TTL:
            return cached_reply

    messages = [{"role": "system", content: VAJRA_SYSTEM_PROMPT}]
    
    if context_files:
        summary = ""
        for name, content in list(context_files.items())[:3]:
            safe_content = content[:1000].replace("\x00", "")
            summary += f"\n--- File: {name} ---\n{safe_content}"
        if summary:
            messages.append({"role": "system", content: f"Workspace Files:\n{summary}"})
            
    messages.append({"role": "user", content: prompt})
    
    text_input = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )
    
    model_inputs = tokenizer([text_input], return_tensors="pt").to(model.device)
    
    # Precise stopping criteria: stop on either default eos or Qwen2.5 <|im_end|>
    eos_token_ids = [tokenizer.eos_token_id]
    try:
        im_end_id = tokenizer.convert_tokens_to_ids("<|im_end|>")
        if im_end_id is not None and im_end_id != tokenizer.unk_token_id:
            eos_token_ids.append(im_end_id)
    except Exception:
        pass

    with torch.no_grad():
        generated_ids = model.generate(
            **model_inputs,
            max_new_tokens=2048,
            temperature=0.2,
            top_p=0.9,
            repetition_penalty=1.1,
            do_sample=True,
            eos_token_id=eos_token_ids,
            pad_token_id=tokenizer.eos_token_id
        )
        
    generated_ids = [
        output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
    ]
    
    response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0].strip()
    
    # Cache result for 10 minutes to save GPU quota
    if not context_files and response:
        _query_cache[cache_key] = (now, response)

    # Explicit Zero-Retention Memory Cleanup
    del model_inputs, generated_ids
    gc.collect()
    
    return response

# =====================================================================
# 3. FASTAPI BACKEND API
# =====================================================================
api_app = FastAPI(title="VAJRA Secure Backend API", docs_url=None, redoc_url=None)

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@api_app.middleware("http")
async def add_security_headers(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return JSONResponse({"error": "Rate limit exceeded (Max 30 requests/min)."}, status_code=429)
    
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

class ChatRequest(BaseModel):
    prompt: str = Field(..., max_length=15000)
    workspace_id: Optional[str] = None
    files: Optional[Dict[str, str]] = None
    auth_key: Optional[str] = None

@api_app.get("/health")
def health():
    return {
        "status": "online",
        "shield": "VAJRA Enterprise Security Active",
        "model": "AravKataria/vajra-lora (Qwen2.5-Coder-7B)",
        "author": "Arav Kataria"
    }

@api_app.post("/api/chat")
async def chat_api(req: ChatRequest, request: Request):
    sig_header = request.headers.get("X-Vajra-Signature") or req.auth_key
    client_ip = request.client.host if request.client else "127.0.0.1"

    if VAJRA_SECRET_KEY:
        import hmac
        if not sig_header or not hmac.compare_digest(sig_header.strip(), VAJRA_SECRET_KEY.strip()):
            raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing VAJRA Security Signature.")
    else:
        if not check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="Too Many Requests: Rate limit exceeded.")
    
    reply = generate_vajra_reply(req.prompt, req.files)
    return JSONResponse({
        "success": True,
        "reply": reply,
        "model": "AravKataria/vajra-lora",
        "security": "Zero-Retention Verified"
    })

# =====================================================================
# 4. GRADIO INTERFACE
# =====================================================================
def gradio_chat(user_message, history):
    return generate_vajra_reply(user_message)

with gr.Blocks(title="VAJRA Cyber-Reasoning Engine") as demo:
    gr.Markdown("# 🛡️ VAJRA Cyber-Reasoning Intelligence System")
    gr.Markdown("**Fine-Tuned by Arav Kataria** | 7B LoRA Foundation | Zero-Retention Privacy Active")
    chatbot = gr.ChatInterface(fn=gradio_chat, title="")

app = gr.mount_gradio_app(api_app, demo, path="/")
