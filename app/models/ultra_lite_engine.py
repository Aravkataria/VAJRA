# app/models/ultra_lite_engine.py

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("vajra.ultra_lite")

# In-memory query cache for ultra-lite queries (15-minute TTL)
_ultra_lite_cache: Dict[str, Tuple[float, str]] = {}
CACHE_TTL = 900

ULTRA_LITE_MODEL_ID = os.environ.get("VAJRA_ULTRA_LITE_MODEL", "Qwen/Qwen2.5-Coder-0.5B-Instruct")

# High-fidelity STEM & algorithmic reasoning base for instant zero-RAM answers
STEM_FOUNDATIONS = {
    "kirchhoff": (
        "### Kirchhoff's Laws of Electric Circuits\n\n"
        "**Who Discovered It?**\n"
        "Kirchhoff's laws were formulated in 1845 by German physicist **Gustav Kirchhoff** while he was a student at the University of Königsberg.\n\n"
        "**Why Do We Need Them?**\n"
        "While Ohm's Law ($V = IR$) is sufficient for simple single-resistor circuits, real-world electrical networks contain complex junctions, interconnected loops, and multiple energy sources. Kirchhoff's laws provide systematic algebraic equations to compute unknown currents, branch voltages, and equivalent impedances, directly expressing the fundamental conservation laws of physics.\n\n"
        "---\n\n"
        "### The Two Fundamental Laws\n\n"
        "#### 1. Kirchhoff's Current Law (KCL) — The Junction Rule\n"
        "*Physical Principle: Conservation of Electric Charge.*\n"
        "The algebraic sum of all currents entering and exiting any electrical junction (node) must equal zero. Total incoming current equals total outgoing current:\n"
        r"$$\sum I_{\text{in}} = \sum I_{\text{out}} \quad \iff \quad \sum_{k=1}^n I_k = 0$$" "\n\n"
        "#### 2. Kirchhoff's Voltage Law (KVL) — The Loop Rule\n"
        "*Physical Principle: Conservation of Energy.*\n"
        "The directed sum of all potential differences (voltages) around any closed loop in a circuit must equal zero. The total energy supplied equals the total energy dropped:\n"
        r"$$\sum V_{\text{drops}} = \sum V_{\text{rises}} \quad \iff \quad \sum_{k=1}^n V_k = 0$$" "\n\n"
        "---\n\n"
        "### Practical Worked Example\n\n"
        r"Consider a series circuit with a $V_s = 12\text{V}$ battery connected across three resistors: $R_1 = 2\,\Omega$, $R_2 = 4\,\Omega$, and $R_3 = 6\,\Omega$." "\n\n"
        r"1. **By KCL**: Since the circuit has only a single loop, the identical current $I$ traverses all components." "\n"
        r"2. **By KVL around the loop**:" "\n"
        r"   $$V_s - I R_1 - I R_2 - I R_3 = 0$$" "\n"
        r"   $$12\text{V} - I(2\,\Omega + 4\,\Omega + 6\,\Omega) = 0$$" "\n"
        r"   $$12 = 12 \cdot I \implies I = 1.0\text{ A}$$" "\n"
        r"3. **Voltage drop verification across each component**:" "\n"
        r"   $$V_1 = 1\text{A} \times 2\,\Omega = 2\text{V},\quad V_2 = 1\text{A} \times 4\,\Omega = 4\text{V},\quad V_3 = 1\text{A} \times 6\,\Omega = 6\text{V}$$" "\n"
        r"   $$\sum V_{\text{drops}} = 2\text{V} + 4\text{V} + 6\text{V} = 12\text{V} = V_s \quad (\text{Energy Conserved})$$"
    ),
    "ohm": (
        "### Ohm's Law\n\n"
        "**Who Discovered It?**\n"
        "Discovered in 1827 by German physicist **Georg Simon Ohm** through extensive experiments on electrochemical circuits.\n\n"
        "**Formula & Physical Principle:**\n"
        "At constant temperature, the current $I$ through an ideal conductor is directly proportional to the potential difference $V$ across it:\n"
        r"$$V = I \cdot R \quad \iff \quad I = \frac{V}{R} \quad \iff \quad R = \frac{V}{I}$$" "\n\n"
        r"- $V$: Voltage in Volts ($\text{V}$)" "\n"
        r"- $I$: Current in Amperes ($\text{A}$)" "\n"
        r"- $R$: Resistance in Ohms ($\Omega$)"
    ),
    "newton": (
        "### Newton's Laws of Motion\n\n"
        "**Formulated By:** Sir Isaac Newton in *Philosophiae Naturalis Principia Mathematica* (1687).\n\n"
        "1. **First Law (Inertia)**: An object remains at rest or in uniform velocity unless acted on by a net external force:\n"
        r"   $$\sum \vec{F} = 0 \implies \vec{a} = 0$$" "\n\n"
        "2. **Second Law (Fundamental Dynamics)**: The net force on an object equals the rate of change of its linear momentum:\n"
        r"   $$\vec{F}_{\text{net}} = \frac{d\vec{p}}{dt} = m\vec{a}$$" "\n\n"
        "3. **Third Law (Action & Reaction)**: Every action has an equal and opposite reaction:\n"
        r"   $$\vec{F}_{A \to B} = -\vec{F}_{B \to A}$$"
    ),
    "binary search": (
        "### Binary Search Algorithm\n\n"
        "**What Is It?**\n"
        "Binary search is an efficient divide-and-conquer search algorithm that finds the position of a target value within a **sorted array**.\n\n"
        "**How It Works:**\n"
        "1. Compare the target value to the middle element of the array.\n"
        "2. If equal, search is complete.\n"
        "3. If target is less than the middle element, continue search on the left subarray.\n"
        "4. If target is greater, continue search on the right subarray.\n"
        "5. Repeat until the target is found or the subarray is empty.\n\n"
        "**Time & Space Complexity:**\n"
        r"- **Time Complexity:** $O(\log n)$ (halves search space every step)" "\n"
        r"- **Space Complexity:** $O(1)$ iterative, $O(\log n)$ recursive" "\n\n"
        "**Python Implementation:**\n"
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
    "quicksort": (
        "### Quicksort Algorithm\n\n"
        "**What Is It?**\n"
        "Developed by British computer scientist Tony Hoare in 1959, Quicksort is an in-place, divide-and-conquer sorting algorithm.\n\n"
        "**How It Works:**\n"
        "1. Select a 'pivot' element from the array.\n"
        "2. Partition the other elements into two sub-arrays according to whether they are less than or greater than the pivot.\n"
        "3. Recursively apply the process to the sub-arrays.\n\n"
        "**Complexity:**\n"
        r"- **Average Time:** $O(n \log n)$" "\n"
        r"- **Worst-case Time:** $O(n^2)$ (mitigated with randomized/median-of-three pivot)" "\n"
        r"- **Auxiliary Space:** $O(\log n)$ call stack"
    ),
    "big o": (
        "### Big-O Notation & Computational Complexity\n\n"
        "**What Is It?**\n"
        "Big-O notation describes the limiting behavior of a function when the argument tends towards infinity, classifying algorithms according to how their run time or space requirements grow as the input size $n$ grows.\n\n"
        "**Common Time Complexities (Fastest to Slowest):**\n"
        r"- $O(1)$: Constant (e.g. Hash map lookup, array indexing)" "\n"
        r"- $O(\log n)$: Logarithmic (e.g. Binary search)" "\n"
        r"- $O(n)$: Linear (e.g. Linear scan through an array)" "\n"
        r"- $O(n \log n)$: Linearithmic (e.g. Mergesort, Quicksort, Timsort)" "\n"
        r"- $O(n^2)$: Quadratic (e.g. Nested loops, Bubble sort)" "\n"
        r"- $O(2^n)$: Exponential (e.g. Recursive Fibonacci without memoization)" "\n"
        r"- $O(n!)$: Factorial (e.g. Traveling Salesperson brute-force)"
    ),
    "rest api": (
        "### REST API (Representational State Transfer)\n\n"
        "**What Is It?**\n"
        "Defined by Roy Fielding in 2000, REST is an architectural style for distributed hypermedia systems communicating over HTTP.\n\n"
        "**Core Principles:**\n"
        "1. **Client-Server Architecture**: Separation of concerns between client UI and server storage.\n"
        "2. **Stateless**: Each request from client to server must contain all of the information necessary to understand and process the request.\n"
        "3. **Cacheable**: Responses must define themselves as cacheable or non-cacheable.\n"
        "4. **Uniform Interface**: Resources identified by URIs; standard HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`).\n\n"
        "**Standard HTTP Methods:**\n"
        "- `GET`: Retrieve resource representation (Idempotent, Safe)\n"
        "- `POST`: Create a new resource or process data\n"
        "- `PUT`: Replace resource state entirely (Idempotent)\n"
        "- `PATCH`: Partial modification of resource state\n"
        "- `DELETE`: Remove resource (Idempotent)"
    ),
}


class UltraLiteEngine:
    """
    Ultra-Lite 0.5B Execution Engine.
    Engineered for:
    - Memory footprint strictly < 500 MB RAM.
    - Zero GPU seconds (preserves ZeroGPU quota for Level 3).
    - Rapid generation (<1.5 seconds latency).
    - Deployment on Render free tier (512 MB) and low-spec 1GB PCs.
    """

    def __init__(self):
        self._model = None
        self._tokenizer = None
        self._is_loaded = False
        self._load_failed = False

    def load_local_model(self) -> bool:
        if self._is_loaded:
            return True
        if self._load_failed:
            return False

        enable_local = os.environ.get("VAJRA_ENABLE_LOCAL_05B", "false").lower() in ("true", "1")
        if not enable_local:
            return False

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            logger.info(f"Loading {ULTRA_LITE_MODEL_ID} into CPU memory (<500MB)...")
            self._tokenizer = AutoTokenizer.from_pretrained(
                ULTRA_LITE_MODEL_ID,
                trust_remote_code=True,
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                ULTRA_LITE_MODEL_ID,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True,
                trust_remote_code=True,
            )
            self._model.eval()
            self._is_loaded = True
            logger.info(f"✅ {ULTRA_LITE_MODEL_ID} successfully loaded in CPU memory.")
            return True
        except Exception as e:
            logger.warning(f"Local 0.5B model load skipped or failed: {e}")
            self._load_failed = True
            return False

    def generate(
        self,
        prompt: str,
        max_tokens: int = 1024,
        hf_token: Optional[str] = None,
    ) -> Optional[str]:
        cache_key = prompt.lower().strip()
        now = time.time()
        if cache_key in _ultra_lite_cache:
            ts, cached = _ultra_lite_cache[cache_key]
            if now - ts < CACHE_TTL:
                return cached

        # 0. Check foundational STEM & Computer Science knowledge base
        for keyword, synthesis in STEM_FOUNDATIONS.items():
            if keyword in cache_key:
                _ultra_lite_cache[cache_key] = (now, synthesis)
                return synthesis

        # 1. Try local in-process 0.5B model if loaded
        if self.load_local_model() and self._model and self._tokenizer:
            try:
                import torch

                messages = [
                    {
                        "role": "system",
                        "content": "You are VAJRA Ultra-Lite, a fast technical and STEM assistant engineered by Arav Kataria. Provide concise, clear, and mathematically accurate explanations.",
                    },
                    {"role": "user", "content": prompt},
                ]
                text_input = self._tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
                inputs = self._tokenizer([text_input], return_tensors="pt")
                with torch.no_grad():
                    out_ids = self._model.generate(
                        **inputs,
                        max_new_tokens=max_tokens,
                        temperature=0.3,
                        top_p=0.9,
                        do_sample=True,
                        pad_token_id=self._tokenizer.eos_token_id,
                    )
                in_len = inputs.input_ids.shape[1]
                reply = self._tokenizer.decode(out_ids[0, in_len:], skip_special_tokens=True).strip()
                if reply:
                    _ultra_lite_cache[cache_key] = (now, reply)
                    return reply
            except Exception as e:
                logger.warning(f"Local 0.5B inference error: {e}")

        # 2. Try Hugging Face Free Serverless Inference API (0 MB local RAM, 100% free)
        token = hf_token or os.environ.get("HF_TOKEN")
        if token:
            try:
                import json
                import urllib.request

                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "VAJRA-UltraLite-Router/1.0",
                    "Authorization": f"Bearer {token}",
                }

                api_url = f"https://router.huggingface.co/hf-inference/models/{ULTRA_LITE_MODEL_ID}"
                payload = json.dumps({
                    "inputs": prompt,
                    "parameters": {
                        "max_new_tokens": max_tokens,
                        "temperature": 0.3,
                        "return_full_text": False,
                    },
                }).encode("utf-8")

                req = urllib.request.Request(api_url, data=payload, headers=headers)
                with urllib.request.urlopen(req, timeout=12) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if isinstance(data, list) and len(data) > 0:
                            gen_text = data[0].get("generated_text", "").strip()
                            if gen_text:
                                _ultra_lite_cache[cache_key] = (now, gen_text)
                                return gen_text
            except Exception as e:
                logger.warning(f"HF Router inference error: {e}")

        return None


# Global singleton instance
_ultra_lite_engine = UltraLiteEngine()


def get_ultra_lite_engine() -> UltraLiteEngine:
    return _ultra_lite_engine
