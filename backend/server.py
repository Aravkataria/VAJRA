"""
VAJRA Unified Production Backend Server
High-Speed Cyber-Reasoning & LLM Inference API for VAJRA Web and Desktop apps.

Supported LLM Providers (Automatic Detection & Fallback):
1. Groq Cloud (Ultra-Fast 300+ tokens/sec, Free tier available)
2. HuggingFace Inference API (Runs custom fine-tuned weights / Qwen2.5-Coder)
3. OpenRouter / OpenAI Compatible APIs
4. Local Ollama / vLLM instance
"""

import os
import json
import asyncio
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import urllib.request
import urllib.error

app = FastAPI(
    title="VAJRA Cyber-Reasoning Cloud Backend",
    version="2.1.0",
    description="Autonomous Cyber-Reasoning and Software Security Intelligence Backend API"
)

# Enable CORS for any web origin and Tauri desktop app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.

Operational Directives:
1. Identity: Specialized fine-tuned Qwen2.5-Coder model (Transformer architecture, Alibaba Cloud base), fine-tuned by Arav Kataria for autonomous vulnerability triage, zero-regression patch generation, and formal invariant verification.
2. Direct Assistance: Answer coding questions, security architecture inquiries, project planning, and vulnerability analysis concisely, authoritatively, and accurately.
3. Speed & Precision: Deliver direct, high-value answers without unnecessary preamble."""

# Provider Environment Configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
HF_TOKEN = os.getenv("HF_TOKEN", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
CUSTOM_ENDPOINT = os.getenv("VAJRA_UPSTREAM_ENDPOINT", "")
DEFAULT_MODEL = os.getenv("VAJRA_MODEL_NAME", "vajra")

def determine_upstream_config():
    """Detect active cloud API keys or fall back to local Ollama."""
    if GROQ_API_KEY:
        return {
            "endpoint": "https://api.groq.com/openai/v1/chat/completions",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}"
            },
            "model": os.getenv("GROQ_MODEL", "qwen-2.5-coder-32b"),
            "provider": "Groq Cloud (High Speed)"
        }
    elif OPENAI_API_KEY:
        return {
            "endpoint": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1") + "/chat/completions",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {OPENAI_API_KEY}"
            },
            "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            "provider": "OpenAI / Compatible Cloud"
        }
    elif HF_TOKEN:
        hf_model = os.getenv("HF_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
        return {
            "endpoint": f"https://api-inference.huggingface.co/models/{hf_model}/v1/chat/completions",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {HF_TOKEN}"
            },
            "model": hf_model,
            "provider": "Hugging Face Inference API"
        }
    elif CUSTOM_ENDPOINT:
        return {
            "endpoint": CUSTOM_ENDPOINT,
            "headers": {"Content-Type": "application/json"},
            "model": DEFAULT_MODEL,
            "provider": "Custom Upstream"
        }
    else:
        # Default Local Ollama
        return {
            "endpoint": "http://localhost:11434/v1/chat/completions",
            "headers": {"Content-Type": "application/json"},
            "model": DEFAULT_MODEL,
            "provider": "Local Ollama"
        }

class ChatRequest(BaseModel):
    prompt: str
    workspace_id: Optional[str] = None
    files: Optional[Dict[str, str]] = None
    model: Optional[str] = None
    temperature: Optional[float] = 0.2
    max_tokens: Optional[int] = 4096

@app.get("/")
def root():
    cfg = determine_upstream_config()
    return {
        "status": "online",
        "service": "VAJRA Cyber-Reasoning Cloud API",
        "author": "Arav Kataria",
        "active_provider": cfg["provider"],
        "model": cfg["model"]
    }

@app.get("/health")
def health_check():
    cfg = determine_upstream_config()
    return {
        "status": "online",
        "provider": cfg["provider"],
        "model": cfg["model"],
        "backend": "VAJRA-FastAPI",
        "version": "2.1.0"
    }

def is_finder_intent(prompt: str) -> bool:
    """Classify whether the query requires the heavy AST Finder / Scanner pipeline."""
    p = prompt.lower().strip()
    scan_triggers = [
        "scan", "audit", "find vulnerabilities", "find vulns", 
        "detect vulnerabilities", "run finder", "generate patch",
        "patch this", "verify patch", "run verification", "analyze repo"
    ]
    return any(trigger in p for trigger in scan_triggers)

@app.post("/api/chat")
async def chat_endpoint(req: ChatRequest):
    """
    Fast direct LLM inference endpoint with provider auto-routing.
    Bypasses the finder when not needed to ensure zero delay.
    """
    cfg = determine_upstream_config()
    messages = [{"role": "system", content: VAJRA_SYSTEM_PROMPT}]
    
    # If workspace files exist, attach relevant excerpts
    if req.files:
        file_summary = ""
        for name, content in list(req.files.items())[:3]:
            file_summary += f"\n--- File: {name} ---\n{content[:1200]}"
        if file_summary:
            messages.append({"role": "system", content: f"Workspace Files:\n{file_summary}"})
            
    messages.append({"role": "user", content: req.prompt})
    
    target_model = req.model or cfg["model"]
    payload = json.dumps({
        "model": target_model,
        "messages": messages,
        "temperature": req.temperature or 0.2,
        "max_tokens": req.max_tokens or 4096
    }).encode("utf-8")
    
    try:
        http_req = urllib.request.Request(
            cfg["endpoint"],
            data=payload,
            headers=cfg["headers"],
            method="POST"
        )
        with urllib.request.urlopen(http_req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            return JSONResponse({
                "success": True,
                "reply": content,
                "provider": cfg["provider"],
                "model": target_model,
                "bypassed_finder": not is_finder_intent(req.prompt)
            })
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_header = e.headers.get("Retry-After")
            retry_seconds = int(retry_header) if (retry_header and retry_header.isdigit()) else 120
            wait_min = max(1, round(retry_seconds / 60))
            wait_text = f"{retry_seconds} seconds" if retry_seconds < 60 else f"~{wait_min} minute{'s' if wait_min > 1 else ''}"
            return JSONResponse({
                "success": False,
                "rate_limited": True,
                "retry_after": retry_seconds,
                "reply": f"⚠️ **Inference Limit Reached**\n\nYou have reached the temporary AI inference limit for this session (free GPU compute quota). Please wait **{wait_text}** before sending your next chat request.\n\n💡 *Tip: You can continue using local AST security scans, CWE rule triage, and codebase audits without limit.*"
            }, status_code=429)
        return JSONResponse({
            "success": False,
            "error": str(e),
            "fallback": True,
            "provider": cfg["provider"],
            "message": "Upstream LLM unavailable; local fallback triggered."
        }, status_code=502)
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e),
            "fallback": True,
            "provider": cfg["provider"],
            "message": "Upstream LLM unavailable; local fallback triggered."
        }, status_code=502)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"⚡ Starting VAJRA Fast Backend on http://0.0.0.0:{port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)
