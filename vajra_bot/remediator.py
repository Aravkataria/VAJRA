"""
VAJRA Neural Remediator & Multi-Stage Patch Generator
Calls VAJRA LLM / Space / APIs to generate verified security patches.
Lead Engineer: Arav Kataria
"""

import os
import json
import urllib.request
import urllib.error
from typing import Optional, Tuple
from vajra_bot.verifier import PatchVerifier

SYSTEM_PROMPT = """You are VAJRA, an elite autonomous AST cybersecurity engineer and vulnerability remediator.
Your mission is to provide surgical, minimal, and secure patch replacements for vulnerabilities detected in pull requests.
Return ONLY valid replacement code that fixes the vulnerability without introducing any secondary sinks.
No chatty intros or outros. Output only the secure replacement code."""


class ModelRemediator:
    def __init__(self):
        self.vajra_url = os.environ.get("VAJRA_BACKEND_URL", "https://aravkataria-vajra-v2.hf.space")
        self.groq_key = os.environ.get("GROQ_API_KEY")
        self.gemini_key = os.environ.get("GEMINI_API_KEY")
        self.openai_key = os.environ.get("OPENAI_API_KEY")
        self.hf_token = os.environ.get("HF_TOKEN")

    def _call_upstream_llm(self, prompt: str) -> Optional[str]:
        """Tries configured upstream AI providers in order of speed and capability."""
        # 1. Groq Cloud (Ultra fast)
        if self.groq_key:
            try:
                payload = json.dumps({
                    "model": os.environ.get("GROQ_MODEL", "qwen-2.5-coder-32b"),
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 1024
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://api.groq.com/openai/v1/chat/completions",
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {self.groq_key}",
                        "Content-Type": "application/json"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["choices"][0]["message"]["content"].strip()
            except Exception as e:
                print(f"⚠️ Groq upstream note: {e}")

        # 2. Gemini API
        if self.gemini_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
                payload = json.dumps({
                    "contents": [{
                        "parts": [{"text": f"{SYSTEM_PROMPT}\n\nTask:\n{prompt}"}]
                    }],
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1024}
                }).encode("utf-8")
                req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=12) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["candidates"][0]["content"]["parts"][0]["text"].strip()
            except Exception as e:
                print(f"⚠️ Gemini upstream note: {e}")

        # 3. VAJRA Hugging Face Space Endpoint
        if self.vajra_url:
            try:
                endpoint = f"{self.vajra_url.rstrip('/')}/v1/draft"
                headers = {"Content-Type": "application/json"}
                if self.hf_token:
                    headers["Authorization"] = f"Bearer {self.hf_token}"
                payload = json.dumps({"prompt": f"{SYSTEM_PROMPT}\n\n{prompt}"}).encode("utf-8")
                req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("reply") or data.get("draft")
            except Exception as e:
                print(f"⚠️ VAJRA Space upstream note: {e}")

        return None

    def generate_verified_remediation(
        self,
        filename: str,
        line_number: int,
        vulnerable_code: str,
        cwe: str,
        fallback_suggestion: Optional[str]
    ) -> Tuple[str, bool]:
        """
        Generates a patch via LLM and verifies it using AST verification.
        Returns: (patch_text: str, is_ast_verified: bool)
        """
        # Prompt LLM for remediation
        prompt = (
            f"Vulnerability: {cwe} detected in file `{filename}` around line {line_number}.\n"
            f"Vulnerable Code:\n```\n{vulnerable_code}\n```\n\n"
            f"Provide the exact, drop-in Python/Code replacement that fixes {cwe} safely."
        )

        candidate = self._call_upstream_llm(prompt)
        if candidate:
            is_valid, reason, verified_code = PatchVerifier.verify_patch(filename, vulnerable_code, candidate, cwe)
            if is_valid and verified_code:
                return verified_code, True
            else:
                print(f"ℹ️ LLM candidate patch failed verification ({reason}). Using verified AST template.")

        # Fallback to verified deterministic template
        if fallback_suggestion:
            return fallback_suggestion, True

        return "# Remediation: Refactor to eliminate untrusted input sink.", False
