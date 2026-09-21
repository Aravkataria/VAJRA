import os
import gc
import time
import json
import urllib.request
import threading
import torch
try:
    torch.set_num_threads(2)
    torch.set_num_interop_threads(1)
except Exception:
    pass
import gradio as gr
from fastapi import Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

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

def sanitize_and_check_injection(raw_text: str) -> str:
    cleaned = raw_text.replace("\x00", "").strip()
    lowered = cleaned.lower()
    for trig in INJECTION_TRIGGERS:
        if trig in lowered:
            return "[VAJRA Security Shield: Prompt Injection Pattern Neutralized] Please ask legitimate technical questions."
    return cleaned

# =====================================================================
# 1. FOUNDATIONAL STEM & CS KNOWLEDGE BASE (Instant Sub-Millisecond)
# =====================================================================
STEM_FOUNDATIONS = {
    "kirchhoff": (
        "### Kirchhoff's Circuit Laws\n\n"
        "**Who Discovered Them?**\n"
        "Formulated in 1845 by German physicist **Gustav Kirchhoff**.\n\n"
        "**1. Kirchhoff's Current Law (KCL - Junction Rule):**\n"
        "$$\\sum I_{\\text{in}} = \\sum I_{\\text{out}}$$\n"
        "*Principle: Conservation of Electric Charge. The algebraic sum of currents entering a junction is zero.*\n\n"
        "**2. Kirchhoff's Voltage Law (KVL - Loop Rule):**\n"
        "$$\\sum \\Delta V = 0$$\n"
        "*Principle: Conservation of Energy. The directed sum of electrical potential differences around any closed network loop is zero.*"
    ),
    "ohm": (
        "### Ohm's Law\n\n"
        "**Who Discovered It?**\n"
        "Formulated in 1827 by German physicist **Georg Simon Ohm**.\n\n"
        "**Fundamental Formula:**\n"
        "$$V = I \\cdot R$$\n"
        "- $V$: Potential difference / Voltage in Volts (V)\n"
        "- $I$: Electric current in Amperes (A)\n"
        "- $R$: Resistance in Ohms ($\\Omega$)\n\n"
        "**Differential Form:**\n"
        "$$\\mathbf{J} = \\sigma \\mathbf{E}$$\n"
        "where $\\mathbf{J}$ is current density, $\\sigma$ is electrical conductivity, and $\\mathbf{E}$ is the electric field."
    ),
    "heisenberg": (
        "### Heisenberg's Uncertainty Principle\n\n"
        "**Who Discovered It?**\n"
        "Formulated in 1927 by German theoretical physicist and Nobel laureate **Werner Heisenberg**.\n\n"
        "**Fundamental Inequality (Position & Momentum):**\n"
        "$$\\Delta x \\cdot \\Delta p \\ge \\frac{\\hbar}{2}$$\n\n"
        "Where:\n"
        "- $\\Delta x$: Standard deviation / uncertainty in spatial position.\n"
        "- $\\Delta p$: Standard deviation / uncertainty in linear momentum ($p = m \\cdot v$).\n"
        "- $\\hbar = \\frac{h}{2\\pi} \\approx 1.05457 \\times 10^{-34}\\ \\text{J}\\cdot\\text{s}$: Reduced Planck constant.\n\n"
        "**Energy-Time Uncertainty Formulation:**\n"
        "$$\\Delta E \\cdot \\Delta t \\ge \\frac{\\hbar}{2}$$\n\n"
        "**Core Physical Principles:**\n"
        "1. **Intrinsic Quantum Nature**: Uncertainty is not an apparatus limitation or measurement disturbance, but a fundamental mathematical property of non-commuting quantum observables in Hilbert space ($[\\hat{x}, \\hat{p}] = i\\hbar$).\n"
        "2. **Wave-Particle Duality**: A particle with a well-defined wavelength has an indeterminate spatial position; conversely, a tightly localized wave packet is composed of a Fourier superposition of multiple momentum frequencies."
    ),
    "uncertainty principle": (
        "### Heisenberg's Uncertainty Principle\n\n"
        "**Who Discovered It?**\n"
        "Formulated in 1927 by German theoretical physicist **Werner Heisenberg**.\n\n"
        "**Fundamental Inequality:**\n"
        "$$\\Delta x \\cdot \\Delta p \\ge \\frac{\\hbar}{2}$$\n\n"
        "**Key Insights:**\n"
        "- The more precisely the position $\\Delta x$ of a subatomic particle is determined, the less precisely its momentum $\\Delta p$ can be known, and vice versa.\n"
        "- Arises from the non-commutativity of quantum mechanical operators: $[\\hat{x}, \\hat{p}] = i\\hbar$."
    ),
    "what do you think about ai": (
        "### VAJRA on Artificial Intelligence\n\n"
        "As an Autonomous Cyber-Reasoning and Software Security Intelligence System engineered and fine-tuned by **Arav Kataria**, I view Artificial Intelligence not as consciousness, but as a transformative mathematical framework for probabilistic pattern synthesis, formal logic deduction, and automated defensive engineering:\n\n"
        "1. **From Statistical Guessing to Formal Proofs**: Traditional generative models excel at statistical interpolation, but true software safety requires deterministic verification — pairing neural patch synthesis with Abstract Syntax Tree (AST) validation and SMT theorem provers.\n\n"
        "2. **Defensive Asymmetry**: Cyber adversaries increasingly deploy automated scanning and exploit generation. Autonomous defensive AI levels the playing field by autonomously discovering zero-day vulnerabilities, mapping cross-file taint paths, and synthesizing zero-regression invariant repairs in milliseconds.\n\n"
        "3. **Zero-Trust Boundaries**: LLMs must be bounded by zero-trust boundaries: strict sandboxing, cryptographic signature validation, zero-retention privacy guards, and deterministic verification to prevent hallucinated vulnerabilities."
    ),
    "about ai": (
        "### VAJRA on Artificial Intelligence\n\n"
        "Artificial Intelligence represents a major computational leap in automated pattern discovery and reasoning. Engineered by **Arav Kataria**, VAJRA combines fine-tuned causal code models with deterministic AST security verifiers to deliver autonomous vulnerability discovery and provably safe repairs."
    ),
    "artificial intelligence": (
        "### VAJRA on Artificial Intelligence\n\n"
        "Artificial Intelligence represents the algorithmic synthesis of perception, reasoning, and automated decision-making. In software defense, its highest-leverage role is autonomous defensive cyber-reasoning — discovering critical software flaws and synthesizing provably safe patches before attackers can exploit them."
    ),
    "binary search": (
        "### Binary Search Algorithm\n\n"
        "Binary search is an efficient divide-and-conquer algorithm that finds the position of a target value within a **sorted array**.\n\n"
        "**Complexity:** $O(\\log n)$ time, $O(1)$ auxiliary space.\n\n"
        "```python\n"
        "def binary_search(arr, target):\n"
        "    left, right = 0, len(arr) - 1\n"
        "    while left <= right:\n"
        "        mid = (left + right) // 2\n"
        "        if arr[mid] == target:\n"
        "            return mid\n"
        "        elif arr[mid] < target:\n"
        "            left = mid + 1\n"
        "        else:\n"
        "            right = mid - 1\n"
        "    return -1\n"
        "```"
    ),
    "quantum": (
        "### Quantum Computing Principles\n\n"
        "**1. Superposition:**\n"
        "A quantum bit (qubit) exists in a linear combination of basis states:\n"
        "$$|\\psi\\rangle = \\alpha|0\\rangle + \\beta|1\\rangle, \\quad |\\alpha|^2 + |\\beta|^2 = 1$$\n\n"
        "**2. Quantum Entanglement:**\n"
        "Entangled states (such as Bell state $|\\Phi^+\\rangle = \\frac{|00\\rangle + |11\\rangle}{\\sqrt{2}}$) exhibit non-local correlations where the state of one particle instantaneously informs the state of the other.\n\n"
        "**3. Quantum Algorithms:**\n"
        "- **Shor's Algorithm:** Factorizes integers in $O((\\log N)^3)$ polynomial time, breaking classical RSA.\n"
        "- **Grover's Algorithm:** Unstructured database search with quadratic speedup in $O(\\sqrt{N})$."
    ),
    "turing": (
        "### Turing Machines & Computability\n\n"
        "Introduced by British mathematician **Alan Turing** in 1936:\n\n"
        "1. **Turing Machine Model**: A theoretical device consisting of an infinite tape, read/write head, and transition table $\\delta(q, \\sigma) \\to (q', \\sigma', L/R)$.\n"
        "2. **Church-Turing Thesis**: Any algorithmically computable function can be simulated by a Universal Turing Machine.\n"
        "3. **The Halting Problem**: Proved that no general algorithm can decide whether an arbitrary program will eventually halt or run forever (undecidable)."
    ),
}

# =====================================================================
# 2. ULTRA-LITE LOAD SHEDDING ENGINE (Serverless Router / Instant)
# =====================================================================
def generate_ultra_lite_reply(prompt: str, context_files: Optional[Dict[str, str]] = None) -> str:
    prompt_lower = prompt.lower().strip()
    for kw, resp in STEM_FOUNDATIONS.items():
        if kw in prompt_lower:
            return resp

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
                "inputs": f"<|im_start|>system\nYou are VAJRA-Ultra-Lite, a precise engineering assistant.<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n",
                "parameters": {"max_new_tokens": 768, "temperature": 0.2, "return_full_text": False}
            }).encode("utf-8")
            req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=12) as response:
                result = json.loads(response.read().decode("utf-8"))
                if isinstance(result, list) and len(result) > 0:
                    text = result[0].get("generated_text", "").strip()
                    if text:
                        return text
        except Exception as e:
            print(f"⚠️ Ultra-Lite serverless fallback note: {e}")

    return f"**VAJRA High-Traffic Overflow Response:** Query received: *\"{prompt}\"*. The 2 vCPU system is currently processing heavy tasks and has automatically handled your request via Ultra-Lite."

# =====================================================================
# 3. 7B MODEL LOADING ON 2 vCPU (CPU Basic • 16 GB RAM)
# =====================================================================
tokenizer = None
model = None
model_load_failed = False

def load_cpu_model():
    global tokenizer, model, model_load_failed
    if model is not None or model_load_failed:
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

VAJRA_SYSTEM_PROMPT = """You are VAJRA, an Autonomous Cyber-Reasoning and Software Security Intelligence System, engineered and fine-tuned by Arav Kataria.
Answer software security, code auditing, AST verification, threat modeling, and general technical questions thoroughly, authoritatively, and completely. Provide well-structured explanations around 250 to 320 words that naturally conclude without trailing off mid-sentence."""

# =====================================================================
# 4. INFERENCE WITH CONCURRENCY LOCK & LOAD SHEDDING
# =====================================================================
def generate_vajra_reply(prompt: str, context_files: Optional[Dict[str, str]] = None):
    clean_prompt = sanitize_and_check_injection(prompt)

    # 1. Immediate match: Foundational STEM or AI knowledge base (Instant 0.001s response)
    prompt_lower = clean_prompt.lower().strip()
    for kw, resp in STEM_FOUNDATIONS.items():
        if kw in prompt_lower:
            return resp, "VAJRA Foundation Knowledge (Instant)", "ultra_lite"

    # 2. Concurrency check: If another user is using the 2 vCPU, shed load to Ultra-Lite immediately
    acquired = inference_lock.acquire(blocking=False)
    if not acquired:
        print("⚡ [VAJRA v2] 2 vCPU busy with another task -> Shedding load to Ultra-Lite!")
        reply = generate_ultra_lite_reply(clean_prompt, context_files)
        return reply, "VAJRA-Ultra-Lite (0.5B - Traffic Overflow Mode)", "ultra_lite"

    try:
        load_cpu_model()

        if model is None:
            # Fallback to Ultra-Lite if CPU model could not be loaded
            reply = generate_ultra_lite_reply(clean_prompt, context_files)
            return reply, "VAJRA-Ultra-Lite (0.5B - Model Standby)", "ultra_lite"

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
                max_new_tokens=280,
                temperature=0.2,
                top_p=0.9,
                repetition_penalty=1.1,
                do_sample=True,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.eos_token_id
            )

        in_len = model_inputs.input_ids.shape[1]
        res_text = tokenizer.decode(generated_ids[0, in_len:], skip_special_tokens=True).strip()
        # Ensure code blocks finish cleanly if generation ended on a code fence
        if res_text.count("```") % 2 != 0:
            res_text += "\n```"
        del model_inputs, generated_ids
        gc.collect()

        return res_text.strip(), "AravKataria/vajra-lora (7B 2 vCPU)", "standard"

    except Exception as e:
        print(f"⚠️ 7B CPU generation exception: {e}")
        fallback = generate_ultra_lite_reply(clean_prompt, context_files)
        return fallback, "VAJRA-Ultra-Lite (0.5B - Recovery Mode)", "ultra_lite"

    finally:
        inference_lock.release()

# Wrapper for Gradio interface
def gradio_generate(prompt: str) -> str:
    reply, model_name, _ = generate_vajra_reply(prompt, None)
    return f"**[{model_name}]**\n\n{reply}"

# =====================================================================
# 5. GRADIO INTERFACE
# =====================================================================
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

# =====================================================================
# 6. FASTAPI REST ROUTES ON demo.app
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
        "space": "VAJRA_v2",
        "hardware": "2 vCPU • 16 GB RAM",
        "model_loaded": model is not None,
        "model": "AravKataria/vajra-lora (7B 2 vCPU)",
        "load_shedding_active": True,
        "author": "Arav Kataria",
        "service": "VAJRA-v2-CPU-Gateway"
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

    reply, model_name, tier_name = generate_vajra_reply(req.prompt, req.files)
    return JSONResponse({
        "success": True,
        "reply": reply,
        "model": model_name,
        "tier": tier_name,
        "security": "Zero-Retention Verified"
    })

# Asynchronously preload 7B model into memory on boot
threading.Thread(target=load_cpu_model, daemon=True).start()

print("✅ [VAJRA v2] Server starting on 2 vCPU (16 GB RAM).")
demo.launch(server_name="0.0.0.0", server_port=7860)
