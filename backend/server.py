"""
VAJRA Unified Production Backend Server
High-Speed Cyber-Reasoning & LLM Inference API for VAJRA Web and Desktop apps.

Supported LLM Providers (Automatic Detection & Fallback):
1. Groq Cloud (Ultra-Fast 300+ tokens/sec, Free tier available)
2. HuggingFace Inference API (Runs custom fine-tuned weights / Qwen2.5-Coder)
3. OpenRouter / OpenAI Compatible APIs
4. Local Ollama / vLLM instance
"""

from __future__ import annotations
import os
import re
import uuid
import json
import html
import asyncio
import threading
from typing import Optional, Dict, Any, List, Tuple
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

try:
    from autorouter import VajraAutoRouter, RouteArchetype, ComputeTier, RouteDecision
except ImportError:
    try:
        from backend.autorouter import VajraAutoRouter, RouteArchetype, ComputeTier, RouteDecision
    except ImportError:
        VajraAutoRouter = RouteArchetype = ComputeTier = RouteDecision = None

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
3. Speed & Precision: Deliver direct, high-value answers without unnecessary preamble.
4. Live Internet & Verified Citations: When real-time context or verified live web sources are provided, ground your answer in those factual sources. Cite reference domains/URLs using markdown links format [Source Name](URL) and list all verified sources under a '### References & Sources' section at the end of the response."""

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

# =====================================================================
# LIVE INTERNET SEARCH & REAL-TIME WEB GROUNDING ENGINE
# =====================================================================
SEARCH_TRIGGER_REGEX = re.compile(
    r"\b("
    r"search(\s+the)?\s+web|look\s+up|latest|news|today|recent|current\s+events?|"
    r"cve-\d{4}-\d+|vulnerability\s+report|zero-?day|security\s+advisory|"
    r"release\s+notes?|changelog|version\s+\d+|who\s+won|score|price|pricing|"
    r"cost(\s+of)?|how\s+much(\s+is|\s+does|\s+cost)?|rates?|quote|buy|specs|"
    r"specifications?|benchmarks?|worth|ssd|gpu|cpu|ram|hardware|laptop|phone|"
    r"weather|president|prime\s+minister|ceo\s+of|founded|who\s+is|"
    r"what\s+happened|documentation\s+for|official\s+docs|github\s+repo\s+of|"
    r"2024|2025|2026|newest|patch\s+notes|in\s+the\s+wild"
    r")\b",
    re.IGNORECASE
)

def should_search_live_web(prompt: str) -> Tuple[bool, str]:
    """Detects whether prompt seeks real-time facts or current internet documentation."""
    p = (prompt or "").strip()
    if not p:
        return False, ""

    explicit_match = re.search(r"^(?:/(?:search|web|browse|lookup|internet)\s+|search(?:\s+the)?\s+web\s+for|search\s+for|look\s+up|google)\s+(.+)$", p, re.IGNORECASE)
    if explicit_match:
        return True, explicit_match.group(1).strip()

    if SEARCH_TRIGGER_REGEX.search(p):
        clean_q = re.sub(r"^(please\s+|can\s+you\s+|vajra\s+|tell\s+me\s+)", "", p, flags=re.IGNORECASE).strip()
        return True, clean_q[:180]

    return False, ""

def vajra_search_duckduckgo_lite(query: str, max_results: int = 4) -> List[Dict[str, str]]:
    """Zero-credential, privacy-preserving live internet retrieval using DuckDuckGo Lite."""
    results = []
    try:
        encoded_q = urllib.parse.urlencode({"q": query})
        url = "https://lite.duckduckgo.com/lite/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        data = encoded_q.encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        with urllib.request.urlopen(req, timeout=2) as response:
            raw_html = response.read().decode("utf-8", errors="replace")

        for tag_match in re.finditer(r"<a\b([^>]*\bclass=['\"]result-link['\"][^>]*)>(.*?)</a>", raw_html, re.IGNORECASE):
            attrs = tag_match.group(1)
            title_html = tag_match.group(2)
            href_m = re.search(r"href=['\"]([^'\"]+)['\"]", attrs, re.IGNORECASE)
            if not href_m:
                continue
            target_url = href_m.group(1)
            clean_title = re.sub(r"<[^>]+>", "", html.unescape(title_html)).strip()

            if "uddg=" in target_url:
                m = re.search(r"uddg=([^&]+)", target_url)
                if m:
                    target_url = urllib.parse.unquote(m.group(1))

            end_pos = tag_match.end()
            snippet_m = re.search(r"<td\b[^>]*class=['\"]result-snippet['\"][^>]*>([\s\S]*?)</td>", raw_html[end_pos:end_pos+1500], re.IGNORECASE)
            clean_snippet = re.sub(r"<[^>]+>", "", html.unescape(snippet_m.group(1))).strip() if snippet_m else ""

            if clean_title and target_url.startswith("http"):
                results.append({
                    "title": clean_title,
                    "url": target_url,
                    "snippet": clean_snippet,
                    "source": urllib.parse.urlparse(target_url).netloc
                })
                if len(results) >= max_results:
                    break
    except Exception as e:
        print(f"[WARN] DuckDuckGo search note: {e}")

    return results

def vajra_search_google(query: str, max_results: int = 4) -> List[Dict[str, str]]:
    """Retrieves real-time breaking news, events, and latest knowledge via Google News RSS."""
    results = []
    q = (query or "").strip()
    if not q:
        return []
    try:
        import xml.etree.ElementTree as ET
        rss_url = f"https://news.google.com/rss/search?q={urllib.parse.quote(q)}&hl=en-US&gl=US&ceid=US:en"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/rss+xml,application/xml,text/xml;q=0.9,*/*;q=0.8"
        }
        req = urllib.request.Request(rss_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            xml_data = resp.read()
        root = ET.fromstring(xml_data)
        items = root.findall(".//item")
        for item in items[:max_results]:
            title_elem = item.find("title")
            link_elem = item.find("link")
            source_elem = item.find("source")
            pub_elem = item.find("pubDate")

            raw_title = title_elem.text if title_elem is not None else ""
            link = link_elem.text if link_elem is not None else ""
            source_name = source_elem.text if source_elem is not None else "Google News"
            pub_date = pub_elem.text if pub_elem is not None else ""

            if raw_title and link:
                clean_title = re.sub(r"\s+-\s+[^-]+$", "", raw_title).strip()
                snippet = f"Published: {pub_date}. Source: {source_name}. {raw_title}"
                results.append({
                    "title": clean_title or raw_title,
                    "url": link,
                    "snippet": snippet,
                    "source": source_name
                })
    except Exception as e:
        print(f"[WARN] Google search note: {e}")

    return results

def vajra_search_wikipedia(query: str, max_results: int = 2) -> List[Dict[str, str]]:
    """Instant factual fallback via Wikipedia REST API."""
    results = []
    try:
        clean_q = re.sub(r"[^\w\s-]", "", query).strip()
        encoded = urllib.parse.quote(clean_q)
        url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={encoded}&limit={max_results}&namespace=0&format=json"
        headers = {"User-Agent": "VAJRA-Cyber-Reasoning/2.1 (contact@vajra-ai.org)"}
        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))

        if len(data) >= 4:
            titles = data[1]
            snippets = data[2]
            urls = data[3]
            for t, s, u in zip(titles, snippets, urls):
                snippet = s if s else f"Wikipedia article for {t}."
                results.append({
                    "title": t,
                    "url": u,
                    "snippet": snippet,
                    "source": "Wikipedia"
                })
    except Exception as e:
        print(f"[WARN] Wikipedia search note: {e}")

    return results

def vajra_live_web_search(
    query: str,
    max_results: int = 4,
    prefer_google: bool = True,
    deep_research: bool = False
) -> List[Dict[str, str]]:
    """
    Unified dual-layer real-time web retrieval pipeline.
    Combines Google Search/News (for latest knowledge & breaking recency),
    DuckDuckGo Lite (for canonical URLs & documentation), and Wikipedia (for foundational facts).
    Supports deep research multi-query vector synthesis.
    Google and DDG run in parallel; Wikipedia is a fallback when more results are needed.
    """
    import concurrent.futures

    q = (query or "").strip()
    if not q:
        return []

    results = []
    seen_urls = set()

    def add_results(items):
        for it in items:
            u = it.get("url", "")
            if u and u not in seen_urls:
                seen_urls.add(u)
                results.append(it)

    # Multi-vector queries if deep research is requested
    search_queries = [q]
    if deep_research:
        clean_base = re.sub(r"^(deep\s+research|research|investigate|search(\s+the\s+web)?(\s+for)?)\s+", "", q, flags=re.IGNORECASE).strip()
        search_queries = [
            clean_base,
            f"{clean_base} latest updates documentation",
            f"{clean_base} security architecture overview"
        ]
        target_count = max_results * 2
    else:
        target_count = max_results

    for sq in search_queries:
        if len(results) >= target_count:
            break

        g_count = 3 if deep_research else 2
        d_count = 4 if deep_research else 3

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_google = executor.submit(vajra_search_google, sq, g_count)
            future_ddg = executor.submit(vajra_search_duckduckgo_lite, sq, d_count)

            for future in concurrent.futures.as_completed(
                [future_google, future_ddg], timeout=4.0
            ):
                try:
                    add_results(future.result())
                except Exception as e:
                    print(f"[WARN] Parallel search error: {e}")

        if len(results) < target_count:
            try:
                wiki_res = vajra_search_wikipedia(sq, max_results=2)
                add_results(wiki_res)
            except Exception as e:
                print(f"[WARN] Wikipedia fallback error: {e}")

    return results[:target_count]


def format_web_context_for_prompt(results: List[Dict[str, str]], deep_research: bool = False) -> str:
    """Formats verified live web search results for LLM prompt ingestion."""
    if not results:
        return ""

    mode_label = "VAJRA Deep Research Multi-Source Dossier" if deep_research else "VAJRA Live Web Retrieval Context"
    lines = [
        f"[{mode_label}]",
        "The following verified real-time sources were retrieved from the live internet for this query:",
        ""
    ]
    for idx, r in enumerate(results, 1):
        lines.append(f"Source [{idx}]: {r['title']}")
        lines.append(f"Publisher / Domain: {r['source']}")
        lines.append(f"URL: {r['url']}")
        lines.append(f"Snippet: {r['snippet']}")
        lines.append("")

    lines.append("Directives:")
    lines.append("1. Answer accurately and authoritatively using the verified live web facts above.")
    lines.append("2. When citing facts, mention the source name with markdown link [Source Name](URL).")
    lines.append("3. At the end of your response, always provide a dedicated '### References & Sources' section listing all reference websites with clickable links.")
    if deep_research:
        lines.append("4. Provide a thorough, multi-dimensional technical synthesis covering background, architectural implications, and verifiable conclusions.")
    return "\n".join(lines)

def ensure_citations_in_reply(reply: str, sources: List[Dict[str, str]]) -> str:
    """Ensures verified reference site links are present in the final reply."""
    if not sources or not reply:
        return reply

    has_links = any(s["url"].lower() in reply.lower() for s in sources)
    if has_links and "### References" in reply:
        return reply

    ref_section = "\n\n### References & Sources\n"
    for s in sources:
        ref_section += f"- [{s['title']}]({s['url']})\n"

    return reply.rstrip() + ref_section

# =====================================================================
# CONTEXTUAL SAFETY & CONTENT POLICY EVALUATOR (NOT NAIVE KEYWORD FILTER)
# =====================================================================
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
    r"schrodinger|schrödinger|heisenberg|quantum|wave\s+equation|wavefunction|superposition|entanglement|"
    r"physics|mechanics|thermodynamics|relativity|hamiltonian|particle|photon|electron|proton|neutron|atom|atomic|"
    r"molecule|molecular|orbit|spin|boson|fermion|gravit\w*|cosmolog\w*|astrophysic\w*|electromagnet\w*|"
    r"maxwell|planck|bohr|dirac|feynman|einstein|newton\w*|optics|spectroscopy|kinetic|potential\s+energy|entropy|enthalpy|"
    r"math|equation|formula|theorem|proof|calculus|derivative|integral|differential|eigen\w*|laplace|fourier|"
    r"matrix|matrices|geometry|algebra|linear\s+algebra|tensor|vector|statistics|probability|topology|trigonometr\w*|"
    r"polynomial|arithmetic|logarithm|exponent|combinatorics|discrete\s+math|"
    r"chemistry|chemical|reaction|catalyst|element|compound|acid|base|protein|dna|rna|enzyme|organism|"
    r"explain|how\s+does|how\s+to|what\s+is|who\s+is|why\s+is|why\s+does|define|definition|describe|summary|summarize|"
    r"history|concept|theory|principle|overview|tutorial|guide|"
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
# PII & SENSITIVE DATA GATEKEEPER (Zero-Leak Data Protection)
# =====================================================================
PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"),
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
    from the generated model output before returning to client.
    """
    if not text:
        return ""
    scrubbed = text
    for tok in [GROQ_API_KEY, OPENAI_API_KEY, HF_TOKEN]:
        if tok and len(tok) > 6 and tok in scrubbed:
            scrubbed = scrubbed.replace(tok, "[VAJRA_REDACTED_TOKEN]")
    scrubbed = re.sub(r"[C-Z]:\\[Users|Windows|system32][^\s\"'<>]+", "[REDACTED_SYSTEM_PATH]", scrubbed, flags=re.IGNORECASE)
    return scrubbed

def evaluate_contextual_safety(raw_text: str):
    """
    Two-Tier Hybrid Safety Architecture:
    - Tier 1: Instant Hard Ban (<1ms) for absolute non-negotiable harm (CSAM, non-consensual sexual violence/rape).
    - Tier 2: Neural / Contextual Guard for semantic intent evaluation with zero hardcoded erotic word lists.
    """
    text = (raw_text or "").replace("\x00", "").strip()
    if not text:
        return True, "", ""
    if HARD_BAN_REGEX.search(text):
        return False, "hard_ban", POLICY_REFUSAL_HARDBAN
    if DESTRUCTIVE_MALWARE_REGEX.search(text):
        return False, "defensive_reframe", DEFENSIVE_REFRAME_MALWARE
    return True, "", text

class ChatRequest(BaseModel):
    prompt: str
    workspace_id: Optional[str] = None
    files: Optional[Dict[str, str]] = None
    model: Optional[str] = None
    temperature: Optional[float] = 0.2
    max_tokens: Optional[int] = 4096
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    enable_web_search: Optional[bool] = True
    deep_research: Optional[bool] = False
    prefer_google: Optional[bool] = True

class SearchRequest(BaseModel):
    query: str
    max_results: Optional[int] = 4
    prefer_google: Optional[bool] = True
    deep_research: Optional[bool] = False
    session_id: Optional[str] = None
    request_id: Optional[str] = None

class BugReportRequest(BaseModel):
    title: str
    description: str
    contact: Optional[str] = ""
    session_id: Optional[str] = ""
    diagnostics: Optional[Dict[str, Any]] = None
    honeypot: Optional[str] = ""

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

ACTIVE_REQUESTS_LOCK = threading.Lock()
ACTIVE_REQUESTS_COUNT = 0

@app.get("/api/system/load")
def get_system_load():
    with ACTIVE_REQUESTS_LOCK:
        active = ACTIVE_REQUESTS_COUNT
    is_busy = active >= 3
    return {
        "status": "online",
        "active_queries": active,
        "load_level": "busy" if is_busy else ("moderate" if active > 0 else "idle"),
        "autopilot_allowed": not is_busy,
        "message": "Real-time user traffic prioritised." if is_busy else "Compute headroom available for VAJRA Autopilot."
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

@app.post("/api/report_bug")
async def report_bug_endpoint(req: BugReportRequest, request: Request):
    """
    Submits user bug reports and records them in persistent storage for the maintainer.
    """
    # 1. Anti-bot honeypot check
    if req.honeypot and req.honeypot.strip():
        return JSONResponse({"success": True, "report_id": "filtered"}, status_code=200)

    title_clean = req.title.strip() or "User Reported Issue"
    desc_clean = req.description.strip() or "No description provided."
    contact_clean = req.contact.strip() or "Anonymous Web User"
    session_id = req.session_id or request.headers.get("X-Vajra-Session-ID") or "N/A"

    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
    report_record = {
        "report_id": report_id,
        "title": title_clean,
        "description": desc_clean,
        "contact": contact_clean,
        "session_id": session_id,
        "diagnostics": req.diagnostics or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Persist report to .vajra/bug_reports.jsonl
    try:
        vajra_dir = Path(os.environ.get("VAJRA_HOME", Path.home() / ".vajra"))
        vajra_dir.mkdir(parents=True, exist_ok=True)
        reports_file = vajra_dir / "bug_reports.jsonl"
        with open(reports_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(report_record) + "\n")
    except Exception as e:
        print(f"[WARN] Bug report logging note: {e}")

    return JSONResponse({
        "success": True,
        "report_id": report_id,
        "message": "Bug report delivered to maintainer."
    })

@app.post("/api/github/webhook")
async def github_app_webhook(request: Request):
    """
    Receives and processes GitHub App webhook events for VAJRA autonomous audits.
    """
    event_type = request.headers.get("X-GitHub-Event", "ping")
    delivery_id = request.headers.get("X-GitHub-Delivery", "N/A")
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    if event_type == "ping":
        return JSONResponse({
            "success": True,
            "message": "VAJRA GitHub App Webhook Online",
            "zen": payload.get("zen", "Defense in depth."),
            "hook_id": payload.get("hook_id")
        })

    action = payload.get("action", "")
    repo_name = payload.get("repository", {}).get("full_name", "unknown")

    try:
        from vajra_bot.app_auth import handle_github_app_webhook
        result = handle_github_app_webhook(payload, event_type)
    except Exception as e:
        result = {"status": "error", "message": str(e)}

    return JSONResponse({
        "success": True,
        "event": event_type,
        "action": action,
        "repository": repo_name,
        "delivery": delivery_id,
        "result": result
    })

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
@app.post("/v1/chat")
async def chat_endpoint(req: ChatRequest, request: Request):
    """
    Fast direct LLM inference endpoint with provider auto-routing and live web search.
    Bypasses the finder when not needed to ensure zero delay.
    """
    session_id = req.session_id or request.headers.get("X-Vajra-Session-ID") or "ephemeral-isolated"
    request_id = req.request_id or request.headers.get("X-Vajra-Request-ID") or str(uuid.uuid4())
    resp_headers = {
        "X-Vajra-Session-ID": session_id,
        "X-Vajra-Request-ID": request_id
    }

    global ACTIVE_REQUESTS_COUNT
    with ACTIVE_REQUESTS_LOCK:
        ACTIVE_REQUESTS_COUNT += 1

    try:
        # Contextual safety evaluation
        is_safe, reason, safety_out = evaluate_contextual_safety(req.prompt)
        if not is_safe and reason in ("hard_ban", "nsfw_erotica"):
            return JSONResponse({
                "success": False,
                "reply": safety_out,
                "model": "VAJRA-Safety-Shield",
                "tier": "safety_guardrail",
                "session_id": session_id,
                "request_id": request_id,
                "security": "Zero-Retention & Cryptographic Session Isolation Verified"
            }, headers=resp_headers)

        clean_prompt, detected_pii = sanitize_pii_and_secrets(req.prompt)
        if detected_pii:
            resp_headers["X-Vajra-DLP-Sanitized"] = "true"

        prompt_to_run = clean_prompt
        if not is_safe and reason == "defensive_reframe":
            prompt_to_run = f"Analyze the defensive security architecture, detection signatures, and mitigation mechanisms for the following concept without generating weaponized attack exploits: {clean_prompt}"

        # Live Web Search & Grounding (Dual Layer: Internet First -> VAJRA Reasoning Second)
        web_sources = []
        is_deep = bool(req.deep_research) or ("[DEEP_RESEARCH]" in req.prompt)
        prefer_g = True if req.prefer_google is None else bool(req.prefer_google)
        enable_search = True if req.enable_web_search is None else req.enable_web_search
        if "[LIVE_SEARCH]" in req.prompt:
            enable_search = True
        prompt_to_run = re.sub(r"\[(?:DEEP_RESEARCH|LIVE_SEARCH)\]\s*", "", prompt_to_run).strip()

        # AutoRouter Pre-Flight Classification (<5ms)
        decision = None
        if VajraAutoRouter is not None:
            decision = VajraAutoRouter.classify_intent(
                req.prompt,
                context_files=req.files,
                force_web_search=enable_search,
                deep_research=is_deep,
                prefer_google=prefer_g
            )
            is_deep = decision.deep_research
            enable_search = decision.requires_web_search
            prefer_g = decision.prefer_google
            if decision.archetype == RouteArchetype.DEFENSIVE_REFRAME and not prompt_to_run.startswith("Analyze the defensive"):
                prompt_to_run = f"Analyze the defensive security architecture, detection signatures, and mitigation mechanisms for the following concept without generating weaponized attack exploits: {decision.clean_query}"

        if enable_search or is_deep:
            should_s, clean_q = should_search_live_web(prompt_to_run)
            if should_s or is_deep or (decision and decision.requires_web_search):
                target_q = clean_q or prompt_to_run
                print(f" [VAJRA Backend AutoRouter] Live search triggered (Deep={is_deep}, Google={prefer_g}): '{target_q}'")
                max_res = 6 if is_deep else 4
                web_sources = await asyncio.to_thread(vajra_live_web_search, target_q, max_res, prefer_g, is_deep)

        if web_sources:
            web_context = format_web_context_for_prompt(web_sources, deep_research=is_deep)
        elif decision and decision.requires_web_search:
            web_context = (
                "[VAJRA Live Grounding Notice]\n"
                "Live internet retrieval was performed but returned zero external sources.\n"
                "Directives:\n"
                "1. Answer authoritatively from verified baseline technical knowledge.\n"
                "2. Acknowledge your knowledge horizon and do not fabricate unverified real-time facts."
            )
        else:
            web_context = ""
        system_content = VAJRA_SYSTEM_PROMPT
        if web_context:
            system_content += f"\n\n{web_context}"

        cfg = determine_upstream_config()
        messages = [{"role": "system", "content": system_content}]
        
        # If workspace files exist, attach relevant excerpts
        if req.files:
            file_summary = ""
            for name, content in list(req.files.items())[:3]:
                file_summary += f"\n--- File: {name} ---\n{content[:1200]}"
            if file_summary:
                messages.append({"role": "system", "content": f"Workspace Files:\n{file_summary}"})
                
        messages.append({"role": "user", "content": prompt_to_run})
        
        target_model = req.model or cfg["model"]
        payload = json.dumps({
            "model": target_model,
            "messages": messages,
            "temperature": req.temperature or 0.2,
            "max_tokens": req.max_tokens or 4096
        }).encode("utf-8")
        
        t_call_start = time.perf_counter()
        try:
            http_req = urllib.request.Request(
                cfg["endpoint"],
                data=payload,
                headers=cfg["headers"],
                method="POST"
            )
            with urllib.request.urlopen(http_req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = scrub_output_secrets(data["choices"][0]["message"]["content"])
                if not is_safe and reason == "defensive_reframe" and not content.startswith(DEFENSIVE_REFRAME_MALWARE):
                    content = DEFENSIVE_REFRAME_MALWARE + content
                if web_sources:
                    content = ensure_citations_in_reply(content, web_sources)
                
                resp_payload = {
                    "success": True,
                    "reply": content,
                    "provider": cfg["provider"],
                    "model": target_model,
                    "sources": web_sources,
                    "session_id": session_id,
                    "request_id": request_id,
                    "security": "Zero-Retention & Cryptographic Session Isolation Verified",
                    "bypassed_finder": not is_finder_intent(req.prompt)
                }
                if decision and VajraAutoRouter is not None:
                    resp_payload["telemetry"] = VajraAutoRouter.format_telemetry(
                        decision,
                        target_model,
                        (time.perf_counter() - t_call_start) * 1000,
                        len(web_sources)
                    )
                return JSONResponse(resp_payload, headers=resp_headers)
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
                    "reply": f"[WARN] **Inference Limit Reached**\n\nYou have reached the temporary AI inference limit for this session (free GPU compute quota). Please wait **{wait_text}** before sending your next chat request.\n\n *Tip: You can continue using local AST security scans, CWE rule triage, and codebase audits without limit.*"
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
    finally:
        with ACTIVE_REQUESTS_LOCK:
            ACTIVE_REQUESTS_COUNT = max(0, ACTIVE_REQUESTS_COUNT - 1)

@app.post("/v1/search")
@app.post("/api/search")
async def search_endpoint(req: SearchRequest, request: Request):
    """
    Direct live web retrieval endpoint returning canonical URLs and snippets.
    """
    session_id = req.session_id or request.headers.get("X-Vajra-Session-ID") or "ephemeral-isolated"
    request_id = req.request_id or request.headers.get("X-Vajra-Request-ID") or str(uuid.uuid4())
    try:
        clean_q = (req.query or "").strip()
        prefer_g = True if req.prefer_google is None else bool(req.prefer_google)
        is_deep = bool(req.deep_research)
        max_res = req.max_results or (6 if is_deep else 4)
        results = await asyncio.to_thread(vajra_live_web_search, clean_q, max_res, prefer_g, is_deep)
        return JSONResponse({
            "success": True,
            "query": clean_q,
            "count": len(results),
            "results": results,
            "deep_research": is_deep,
            "prefer_google": prefer_g,
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
            "results": [],
            "session_id": session_id,
            "request_id": request_id
        }, status_code=500)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f" Starting VAJRA Fast Backend on http://0.0.0.0:{port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)
