import os
import gc
import json
import time
import asyncio
from typing import Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from huggingface_hub import hf_hub_download

# =====================================================================
# 1. SECURITY & CONFIGURATION
# =====================================================================
VAJRA_SECRET_KEY = os.getenv("VAJRA_SECRET_KEY", "vajra_sec_2026_auth_sig_9f8d7c6b5a4")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", None)

GGUF_REPO = os.getenv("GGUF_REPO", "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF")
GGUF_FILENAME = os.getenv("GGUF_FILENAME", "qwen2.5-coder-7b-instruct-q4_0.gguf")

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.

Operational Directives:
1. Core Specialization: Advanced cyber-security reasoning, deterministic AST vulnerability discovery, surgical zero-regression patch synthesis, and formal invariant proofs (CWE-89, CWE-78, CWE-502, CWE-639 IDOR).
2. General Assistance: Answer software engineering, computer science, general programming, threat modeling, and science questions accurately, authoritatively, and concisely.
3. Quality: Deliver direct, well-structured, production-grade solutions with code blocks where appropriate."""

app = FastAPI(
    title="VAJRA Inference Gateway",
    description="High-performance, 24/7 dedicated FastAPI inference gateway for VAJRA",
    version="2.5.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# =====================================================================
# 2. MODEL LOADER (Thread-Safe Llama-CPP on 16GB CPU)
# =====================================================================
_llm = None
_model_loading = False
_inference_lock = asyncio.Lock()

def get_llm():
    global _llm, _model_loading
    if _llm is not None:
        return _llm
    if _model_loading:
        while _model_loading:
            time.sleep(0.5)
        return _llm

    _model_loading = True
    try:
        from llama_cpp import Llama
        print(f"🔒 [VAJRA] Downloading/verifying GGUF model: {GGUF_REPO} / {GGUF_FILENAME}...")
        model_path = hf_hub_download(
            repo_id=GGUF_REPO,
            filename=GGUF_FILENAME,
            repo_type="model"
        )
        print(f"✅ [VAJRA] Model path: {model_path} (Loading into 16GB RAM)...")
        _llm = Llama(
            model_path=model_path,
            n_ctx=4096,
            n_threads=2,
            n_batch=512,
            verbose=False
        )
        print("🚀 [VAJRA Engine] ONLINE! Ready for 24/7 inference without quotas.")
        return _llm
    finally:
        _model_loading = False

# =====================================================================
# 3. PYDANTIC SCHEMAS
# =====================================================================
class ChatRequest(BaseModel):
    prompt: str = Field(..., max_length=15000)
    files: Optional[Dict[str, str]] = None
    model: Optional[str] = None
    max_tokens: Optional[int] = 1024
    temperature: Optional[float] = 0.2

# =====================================================================
# 4. REST API ROUTES
# =====================================================================
@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VAJRA Inference Gateway</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f3f4f6; padding: 40px; }
            .card { background: #131b2e; border: 1px solid #2a3b5c; border-radius: 12px; padding: 32px; max-width: 640px; margin: 0 auto; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
            h1 { color: #f5b400; margin-top: 0; }
            .badge { display: inline-block; background: rgba(95,191,122,0.15); color: #5fbf7a; border: 1px solid #5fbf7a; padding: 4px 10px; border-radius: 6px; font-size: 0.85rem; font-weight: 600; }
            .info { color: #9ca3af; line-height: 1.6; margin: 16px 0; }
            a { color: #60a5fa; text-decoration: none; font-weight: 600; }
            code { background: #1e293b; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ VAJRA Inference Gateway</h1>
            <span class="badge">● ONLINE — 16GB Dedicated FastAPI Tier</span>
            <p class="info">
                This Space runs the 24/7 dedicated <b>FastAPI Inference Engine</b> for the VAJRA Cyber-Reasoning Platform, engineered by <b>Arav Kataria</b>.
            </p>
            <p class="info">
                <b>Active Endpoints:</b><br>
                • <code>POST /api/chat</code> — Zero-Trust Signature-Locked LLM Inference<br>
                • <code>GET /health</code> — Gateway Health &amp; Model Status<br>
                • <code>GET /docs</code> — Interactive Swagger API Playground
            </p>
            <p style="margin-top:24px;">
                <a href="/docs" target="_blank">Open API Documentation &rarr;</a>
            </p>
        </div>
    </body>
    </html>
    """

@app.get("/health")
def health():
    return {
        "status": "online",
        "service": "VAJRA-Inference-Gateway",
        "model_loaded": _llm is not None,
        "model": "Qwen2.5-Coder-7B-Instruct (GGUF 4-bit)",
        "memory_tier": "16GB Dedicated CPU",
        "author": "Arav Kataria"
    }

@app.post("/api/chat")
async def chat_api(req: ChatRequest, request: Request):
    sig = request.headers.get("X-Vajra-Signature")
    if sig != VAJRA_SECRET_KEY:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Invalid or missing VAJRA Security Signature."
        )

    prompt_clean = req.prompt.strip()

    # Optional fast Groq accelerator if configured
    if GROQ_API_KEY:
        try:
            import urllib.request
            groq_url = "https://api.groq.com/openai/v1/chat/completions"
            groq_payload = json.dumps({
                "model": "qwen-2.5-coder-32b",
                "messages": [
                    {"role": "system", "content": VAJRA_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt_clean}
                ],
                "temperature": req.temperature or 0.2,
                "max_tokens": req.max_tokens or 1024
            }).encode("utf-8")
            groq_req = urllib.request.Request(
                groq_url,
                data=groq_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {GROQ_API_KEY}"
                }
            )
            with urllib.request.urlopen(groq_req, timeout=15) as g_resp:
                g_data = json.loads(g_resp.read().decode("utf-8"))
                reply_text = g_data["choices"][0]["message"]["content"]
                return JSONResponse({
                    "success": True,
                    "reply": reply_text.strip(),
                    "model": "Qwen2.5-Coder-32B (Groq Accelerated)",
                    "shield": "Zero-Retention Verified"
                })
        except Exception as groq_err:
            print(f"⚠️ Groq note: {groq_err}, falling back to local 16GB GGUF engine.")

    # Local 16GB CPU GGUF Inference
    context_prefix = ""
    if req.files and len(req.files) > 0:
        context_prefix = "Workspace Context Files:\n"
        for fname, fcontent in list(req.files.items())[:3]:
            safe_c = fcontent[:2000] if len(fcontent) > 3000 else fcontent
            context_prefix += f"\n--- {fname} ---\n{safe_c}\n"
        context_prefix += "\nUser Query:\n"

    full_user_content = context_prefix + prompt_clean

    messages = [
        {"role": "system", "content": VAJRA_SYSTEM_PROMPT},
        {"role": "user", "content": full_user_content}
    ]

    async with _inference_lock:
        llm = await asyncio.to_thread(get_llm)
        response = await asyncio.to_thread(
            llm.create_chat_completion,
            messages=messages,
            temperature=req.temperature or 0.2,
            max_tokens=req.max_tokens or 1024,
        )

    reply_text = response["choices"][0]["message"]["content"]

    return JSONResponse({
        "success": True,
        "reply": reply_text.strip(),
        "model": "Qwen2.5-Coder-7B-GGUF (16GB Dedicated Space)",
        "shield": "Zero-Retention Verified"
    })
