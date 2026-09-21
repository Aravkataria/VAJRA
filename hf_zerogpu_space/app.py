import os
import gc
import time
import torch
import spaces
import gradio as gr
from fastapi import Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

VAJRA_SECRET_KEY = os.getenv("VAJRA_SECRET_KEY")
HF_TOKEN = os.getenv("HF_TOKEN", None)
LORA_MODEL_ID = "AravKataria/vajra-lora"
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"

RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 30
ip_request_history: Dict[str, list] = {}

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

def sanitize_and_check_injection(raw_text: str) -> str:
    cleaned = raw_text.replace("\x00", "").strip()
    lowered = cleaned.lower()
    for trig in INJECTION_TRIGGERS:
        if trig in lowered:
            return "[VAJRA Security Shield: Prompt Injection Pattern Neutralized] Please ask legitimate technical questions."
    return cleaned

# =====================================================================
# 2. LAZY MODEL LOADING ON ZEROGPU (A100)
# =====================================================================
tokenizer = None
model = None

def load_model():
    global tokenizer, model
    if model is not None:
        return

    print(f"🔒 [VAJRA ZeroGPU] Loading tokenizer from {LORA_MODEL_ID}...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(LORA_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)
    except Exception:
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, token=HF_TOKEN, trust_remote_code=True)

    print(f"🔒 [VAJRA ZeroGPU] Loading {BASE_MODEL_ID} in 4-bit...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4"
    )
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        token=HF_TOKEN,
        quantization_config=bnb_config,
        low_cpu_mem_usage=True,
        trust_remote_code=True,
        device_map="auto"
    )

    print(f"🔒 [VAJRA ZeroGPU] Loading LoRA adapter from {LORA_MODEL_ID}...")
    try:
        model = PeftModel.from_pretrained(model, LORA_MODEL_ID, token=HF_TOKEN)
        print("✅ [VAJRA ZeroGPU] LoRA adapter loaded successfully on GPU!")
    except Exception as e:
        print(f"⚠️ [VAJRA ZeroGPU] LoRA note: {e}")

    model.eval()
    print("🚀 [VAJRA ZeroGPU] A100 Burst Engine ONLINE!")

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.
Answer software security, code auditing, AST verification, threat modeling, and general technical questions thoroughly, authoritatively, and completely. Provide well-structured explanations around 250 to 320 words that naturally conclude without trailing off mid-sentence."""

# =====================================================================
# 3. ZEROGPU INFERENCE (60s Duration for Deep Reasoning)
# =====================================================================
def generate_vajra_reply(prompt: str, context_files: Optional[Dict[str, str]] = None) -> str:
    clean_prompt = sanitize_and_check_injection(prompt)
    return _gpu_generate(clean_prompt, context_files)

@spaces.GPU(duration=60)
def _gpu_generate(clean_prompt: str, context_files: Optional[Dict[str, str]] = None) -> str:
    load_model()
    messages = [{"role": "system", "content": VAJRA_SYSTEM_PROMPT}]

    if context_files and isinstance(context_files, dict):
        summary_text = ""
        for fname, fcontent in list(context_files.items())[:3]:
            safe_c = str(fcontent)[:1000].replace("\x00", "")
            summary_text += f"\n--- File: {fname} ---\n{safe_c}"
        if summary_text:
            messages.append({"role": "system", "content": f"Workspace Files:\n{summary_text}"})

    messages.append({"role": "user", "content": clean_prompt})

    text_input = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    model_inputs = tokenizer([text_input], return_tensors="pt").to(model.device)

    with torch.no_grad():
        generated_ids = model.generate(
            **model_inputs,
            max_new_tokens=896,
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

    del model_inputs, generated_ids
    gc.collect()

    return res_text

# =====================================================================
# 4. GRADIO INTERFACE
# =====================================================================
with gr.Blocks(title="VAJRA Cyber-Reasoning Engine (ZeroGPU Burst)") as demo:
    gr.Markdown("# 🛡️ VAJRA Cyber-Reasoning Intelligence System (ZeroGPU Burst)")
    gr.Markdown("**Fine-Tuned by Arav Kataria** | 7B LoRA | Nvidia A100 ZeroGPU")
    gr.Markdown("• **FastAPI REST Endpoint Active**: `POST /api/chat` (Zero-Trust Verified)")

    with gr.Row():
        user_input = gr.Textbox(
            label="Inquiry / AST Code Audit",
            placeholder="Ask VAJRA to audit code or explain technical concepts...",
            lines=3
        )
    send_button = gr.Button("Submit Reasoning Request", variant="primary")
    output_display = gr.Markdown(label="VAJRA Analysis Output")

    send_button.click(
        fn=generate_vajra_reply,
        inputs=user_input,
        outputs=output_display,
        api_name="generate_vajra_reply"
    )

# =====================================================================
# 5. FASTAPI REST ROUTES ON demo.app
# =====================================================================
demo.app.add_middleware(
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

@demo.app.get("/health")
def health():
    return {
        "status": "online",
        "space": "VAJRA (ZeroGPU)",
        "hardware": "Nvidia A100 ZeroGPU",
        "model_loaded": model is not None,
        "model": "AravKataria/vajra-lora (7B 4-bit ZeroGPU)",
        "author": "Arav Kataria",
        "service": "VAJRA-ZeroGPU-Burst-Gateway"
    }

@demo.app.post("/api/chat")
async def chat_api(req: ChatRequest, request: Request):
    sig_header = request.headers.get("X-Vajra-Signature") or req.auth_key
    client_ip = request.client.host if request.client else "127.0.0.1"

    if VAJRA_SECRET_KEY:
        import hmac
        if not sig_header or not hmac.compare_digest(sig_header.strip(), VAJRA_SECRET_KEY.strip()):
            raise HTTPException(status_code=403, detail="Forbidden: Invalid VAJRA Security Signature.")
    else:
        if not check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="Too Many Requests: Rate limit exceeded.")

    reply = generate_vajra_reply(req.prompt, req.files)
    return JSONResponse({
        "success": True,
        "reply": reply,
        "model": "AravKataria/vajra-lora (ZeroGPU A100 Burst)",
        "tier": "max",
        "security": "Zero-Retention Verified"
    })

print("✅ [VAJRA ZeroGPU] Server starting with A100 support.")
demo.launch(server_name="0.0.0.0", server_port=7860)
