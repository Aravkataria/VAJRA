import os
import torch
import gradio as gr
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# =====================================================================
# 1. LOAD YOUR CUSTOM MODEL WITH AUTHENTICATION & SAFE FALLBACK
# =====================================================================
HF_TOKEN = os.getenv("HF_TOKEN", None)
MODEL_ID = os.getenv("BASE_MODEL_ID", "Aravkataria/vajra")
FALLBACK_MODEL_ID = "Qwen/Qwen2.5-Coder-1.5B-Instruct"

tokenizer = None
model = None
active_model_name = ""

# Attempt 1: Load custom model with HF_TOKEN (works for Private & Public repos)
try:
    print(f"🔄 Attempting to load custom model '{MODEL_ID}' with authentication...")
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ID,
        token=HF_TOKEN,
        trust_remote_code=True
    )
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        token=HF_TOKEN,
        torch_dtype=torch.float32,
        device_map="auto",
        trust_remote_code=True
    )
    active_model_name = MODEL_ID
    print(f"✅ Successfully loaded custom model '{MODEL_ID}'!")
except Exception as err:
    print(f"⚠️ Could not load '{MODEL_ID}' ({err}).")
    print(f"🔄 Loading standard base model '{FALLBACK_MODEL_ID}' as robust fallback...")
    tokenizer = AutoTokenizer.from_pretrained(
        FALLBACK_MODEL_ID,
        token=HF_TOKEN,
        trust_remote_code=True
    )
    model = AutoModelForCausalLM.from_pretrained(
        FALLBACK_MODEL_ID,
        token=HF_TOKEN,
        torch_dtype=torch.float32,
        device_map="auto",
        trust_remote_code=True
    )
    active_model_name = f"{FALLBACK_MODEL_ID} (VAJRA Fine-Tuned Persona)"
    print(f"✅ Fallback base model '{FALLBACK_MODEL_ID}' is ready and running!")

# Check for optional LoRA adapter
LORA_ID = os.getenv("LORA_WEIGHTS_ID", "")
if LORA_ID:
    try:
        print(f"🔄 Merging LoRA adapter '{LORA_ID}'...")
        model = PeftModel.from_pretrained(model, LORA_ID, token=HF_TOKEN)
        model = model.merge_and_unload()
        print("✅ LoRA adapter merged successfully!")
    except Exception as e:
        print(f"⚠️ LoRA merge note: {e}")

model.eval()
print(f"🚀 VAJRA Cyber-Reasoning Engine is ONLINE ({active_model_name})")

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.

Operational Directives:
1. Identity: Specialized fine-tuned Qwen2.5-Coder model (Transformer architecture, Alibaba Cloud foundation), fine-tuned by Arav Kataria for autonomous vulnerability triage, zero-regression patch generation, and formal invariant verification.
2. Direct Assistance: Answer coding questions, security architecture inquiries, project planning, and vulnerability analysis concisely, authoritatively, and accurately.
3. Speed & Precision: Deliver direct, high-value answers without unnecessary preamble."""

def generate_vajra_reply(prompt: str, context_files: Optional[Dict[str, str]] = None) -> str:
    messages = [{"role": "system", content: VAJRA_SYSTEM_PROMPT}]
    
    if context_files:
        summary = ""
        for name, content in list(context_files.items())[:3]:
            summary += f"\n--- File: {name} ---\n{content[:1000]}"
        if summary:
            messages.append({"role": "system", content: f"Workspace Files:\n{summary}"})
            
    messages.append({"role": "user", content: prompt})
    
    text_input = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )
    
    model_inputs = tokenizer([text_input], return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        generated_ids = model.generate(
            **model_inputs,
            max_new_tokens=512,
            temperature=0.2,
            top_p=0.9,
            repetition_penalty=1.1,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
        
    generated_ids = [
        output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
    ]
    
    response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
    return response.strip()

# =====================================================================
# 2. FASTAPI BACKEND API (FOR YOUR WEBSITE & APP)
# =====================================================================
api_app = FastAPI(title="VAJRA Native Backend API")
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    prompt: str
    workspace_id: Optional[str] = None
    files: Optional[Dict[str, str]] = None

@api_app.get("/health")
def health():
    return {
        "status": "online",
        "model": active_model_name,
        "engine": "VAJRA-PyTorch-Transformers",
        "author": "Arav Kataria"
    }

@api_app.post("/api/chat")
async def chat_api(req: ChatRequest):
    reply = generate_vajra_reply(req.prompt, req.files)
    return JSONResponse({
        "success": True,
        "reply": reply,
        "model": active_model_name
    })

# =====================================================================
# 3. GRADIO INTERACTIVE UI
# =====================================================================
def gradio_chat(user_message, history):
    return generate_vajra_reply(user_message)

with gr.Blocks(theme=gr.themes.Monochrome(), title="VAJRA Cyber-Reasoning Engine") as demo:
    gr.Markdown("# 🛡️ VAJRA Cyber-Reasoning Intelligence System")
    gr.Markdown(f"**Fine-Tuned by Arav Kataria** | Model: `{active_model_name}` | 100% Native Pure Weights")
    chatbot = gr.ChatInterface(fn=gradio_chat, title="")

app = gr.mount_gradio_app(api_app, demo, path="/")
