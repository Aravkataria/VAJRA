# VAJRA
 
**Vulnerability Analysis, Judgment, Repair & Assurance**
 
### Evidence-Driven Autonomous Cyber-Reasoning & Software Repair System
 
**Status:** Active research & production-ready sovereign security platform, featuring a 3-tier independent AI model architecture, a native multithreaded Rust core engine (`vajra-core`), a 7-stage independent verification proof matrix (including an SMT formal constraint solver), a universal multi-language Code Property Graph (CPG) engine, a risk-based blast radius prioritizer, a patch minimality evaluator, long-term adaptive learning, and a dual-shell client (a 100% serverless web edition plus a native desktop/CLI edition).
 
**Platforms:** macOS, Windows, Linux · **Core:** Multithreaded Rust (Rayon) · **License:** Apache 2.0 · **Language:** Python 3.10+
 
---
 
## Get VAJRA
 
| Platform | Download / Action | One-line install |
| :--- | :--- | :--- |
| Web Browser | [Launch the live web app](https://Aravkataria.github.io/VAJRA/) — zero install | Runs directly on GitHub Pages |
| Windows | [Download VAJRA-Setup.exe](https://github.com/Aravkataria/VAJRA/releases/latest/download/VAJRA-Setup.exe) — NSIS setup wizard | `irm https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.ps1 \| iex` |
| macOS | [Download VAJRA-macOS.dmg](https://github.com/Aravkataria/VAJRA/releases/latest/download/VAJRA-macOS.dmg) — Apple Silicon DMG | `curl -fsSL https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.sh \| bash` |
| Linux | [Download VAJRA-Linux.AppImage](https://github.com/Aravkataria/VAJRA/releases/latest/download/VAJRA-Linux.AppImage) — universal AppImage | `curl -fsSL https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.sh \| bash` |
 
---
 
## Executive Summary
 
VAJRA is an evidence-driven cyber-reasoning and software-repair platform that connects the entire vulnerability-remediation lifecycle end to end, rather than stopping at "here's a list of problems" the way most scanners do:
 
```text
Discover (Static AST + Rayon Rust Scanner)
   ↓
Confirm (Tier 1: Security Analyst Model)
   ↓
Understand & Prioritize (Risk Score & Blast Radius Engine)
   ↓
Retrieve Causal Intent & Learned Memory (.vajra/knowledge_graph.json)
   ↓
Decide (Deterministic Fast Path vs Tier 2 Reasoning Model)
   ↓
Synthesize Minimal Patch (Patch Minimality & Cyclomatic Delta Evaluator)
   ↓
Generate Targeted Exploit PoC Sentinels & Fuzz Corpus
   ↓
Verify Independently (Tier 3 Adversarial 7-Stage Proof Matrix)
   ↓
Accept / Reject Atomically (Adaptive Learning Feedback Loop)
   ↓
Produce an Auditable Cryptographic Repair Assurance Record
```
 
The central design principle behind all of this: **the reasoning model is never the source of truth**. Specialized static and dynamic analyzers produce concrete evidence, the Decision Engine chooses a repair strategy from that evidence, repair synthesizers construct minimal candidate diffs, and an independent verification matrix — including SMT formal proving — rigorously checks patch correctness before any code is applied. In other words, an AI model is allowed to *propose* a fix, but it is never trusted to *grade its own work*.
 
---
 
## Table of Contents
 
1. [Project Vision & Philosophy](#1-project-vision--philosophy)
2. [3-Tier Sovereign Model Architecture](#2-3-tier-sovereign-model-architecture)
3. [Native Rust Core Engine (vajra-core)](#3-native-rust-core-engine-vajra-core)
4. [Dual-Shell Client (Web vs Desktop)](#4-dual-shell-client-web-vs-desktop)
5. [Complete End-to-End Workflow](#5-complete-end-to-end-workflow)
6. [The 7-Stage Independent Verification Matrix](#6-the-7-stage-independent-verification-matrix)
7. [Universal Multi-Language Code Property Graph (CPG)](#7-universal-multi-language-code-property-graph-cpg)
8. [Risk Prioritization & Blast Radius Engine](#8-risk-prioritization--blast-radius-engine)
9. [Patch Minimality & Complexity Evaluator](#9-patch-minimality--complexity-evaluator)
10. [Long-Term Adaptive Learning & Outcome Tracking](#10-long-term-adaptive-learning--outcome-tracking)
11. [Empirical Benchmark Telemetry & Visualizer](#11-empirical-benchmark-telemetry--visualizer)
12. [Supported Vulnerabilities & Repair Transformation Catalog](#12-supported-vulnerabilities--repair-transformation-catalog)
13. [Decision Engine & Repair Routing](#13-decision-engine--repair-routing)
14. [Universal Bootstrapper & Self-Updating Engine](#14-universal-bootstrapper--self-updating-engine)
15. [Repository Structure](#15-repository-structure)
16. [Installation & Bootstrapping Guide](#16-installation--bootstrapping-guide)
17. [Command-Line Interface (CLI) Reference](#17-command-line-interface-cli-reference)
18. [REST API Gateway Reference](#18-rest-api-gateway-reference)
19. [CI/CD Pipeline & GitHub Actions Integration](#19-cicd-pipeline--github-actions-integration)
20. [Testing & Validation Suite](#20-testing--validation-suite)
21. [Configuration & Environment Variables](#21-configuration--environment-variables)
22. [Security Model & Sandbox Containment](#22-security-model--sandbox-containment)
23. [Evidence Schema & Cryptographic Assurance Record](#23-evidence-schema--cryptographic-assurance-record)
24. [Technology Strategy & Scalability](#24-technology-strategy--scalability)
25. [What VAJRA Does Not Claim](#25-what-vajra-does-not-claim)
26. [Research Questions & Evaluation](#26-research-questions--evaluation)
27. [License](#27-license)
---
 
# 1. Project Vision & Philosophy
 
VAJRA exists to eliminate the fatal flaws of both traditional static application security testing (SAST) tools and unconstrained LLM code generators:
 
1. **Traditional SAST tools** produce massive lists of alerts with no verified fix attached, which overwhelms development teams and trains them to ignore the noise.
2. **Generative AI code models**, left unconstrained, produce plausible-looking code that frequently hallucinates invalid APIs, breaks surrounding logic, or introduces subtle regressions — confidence with no proof behind it.
VAJRA's answer to both problems is a single operating principle: **Evidence, Not Confidence.**
 
- **Evidence First** — a vulnerability is only treated as actionable if a deterministic AST trace or a dynamic sentinel *proves* the presence of an exploitable execution sink. No guessing from pattern-matching alone.
- **Minimal Surgical Patching** — rather than rewriting whole files (which is where most AI-generated regressions come from), VAJRA synthesizes the smallest AST transformation that removes the weakness.
- **Independent Proof Requirement** — code is never trusted just because an AI model generated it. Every candidate patch has to score a full **7 / 7 PASS** across seven independent, adversarial verification stages before it is ever applied to a real file.
---
 
# 2. 3-Tier Sovereign Model Architecture
 
VAJRA deliberately splits reasoning across three separate model roles, so that no single model is ever asked to both propose and approve its own work:
 
```text
┌────────────────────────────────────────────────────────────────────────┐
│                  TIER 1: SECURITY ANALYST MODEL (Confirmatory)         │
│  • Inputs: Static AST findings + surrounding code context.             │
│  • Role: Confirms whether a raw scanner finding is a genuine,          │
│          exploitable weakness, and produces structured evidence.       │
│  • INVARIANT: Confirms/classifies findings; NEVER writes patches.      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 TIER 2: REPAIR REASONING MODEL (Prescriptive)          │
│  • Inputs: Normalized Evidence + Causal Git Intent Invariants.         │
│  • Role: Synthesizes minimal surgical AST patch diffs.                 │
│  • INVARIANT: Proposes candidate repairs; NEVER validates itself.      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│              TIER 3: VERIFICATION & TEST MODEL (Adversarial)           │
│  • Inputs: Original Vulnerability + Proposed Candidate Patch.          │
│  • Role: Generates dynamic exploit PoC payloads, fuzzing boundaries,   │
│          and 3 adversarial patch mutants.                              │
│  • INVARIANT: Strictly adversarial; attempts to break the patch.       │
└────────────────────────────────────────────────────────────────────────┘
```
 
Each tier has exactly one job and is structurally prevented from doing the others. Tier 1 decides *"is this real?"*, Tier 2 decides *"how do we fix it?"*, and Tier 3 spends its entire effort trying to prove Tier 2 wrong. A patch only survives if it can withstand a model whose sole purpose is to break it.
 
> **Note:** the diagram above includes the Tier 1 (Security Analyst) box reconstructed from what the rest of this document already says about Tier 1's role — the diagram itself was missing that box in the source draft. Worth double-checking against your actual `model_independence.py` wording before publishing.
 
---
 
# 3. Native Rust Core Engine (`vajra-core`)
 
To enable ultra-high-throughput scanning on multi-million-line monorepos, VAJRA includes a native multithreaded Rust core crate at [`crates/vajra-core`](crates/vajra-core):
 
- **High-Concurrency Scanner** (`src/scanner.rs`) — uses `rayon` parallel iterators and compiled regexes to scan thousands of files per second across every available CPU core.
- **In-Memory Patch Mutation Engine** (`src/mutation.rs`) — synthesizes three adversarial mutant variants in memory (`REINJECT_UNSAFE_SINK`, `STRIP_VALIDATION_GUARD`, `PARAMETER_PERTURBATION`) and computes exact kill scores in sub-millisecond time.
- **Boundary Fuzz Corpus Synthesizer** (`src/fuzzer.rs`) — a high-throughput byte generator that produces buffer-overflow payloads (64 KB and larger), command metacharacters, null-byte encodings, unicode bypasses, and path-traversal vectors.
- **Causal Git History Archaeologist** (`src/git_history.rs`) — inspects line-level blame and commit intent at native binary speed, so repairs can be informed by *why* a line was written the way it was.
- **Zero-Failure Fallback Guarantee** — the Python adapter ([`app/analysis/adapters/rust_adapter.py`](app/analysis/adapters/rust_adapter.py)) automatically detects whether the compiled Rust binary is present and falls back to pure-Python AST parsing if it isn't, so a missing binary never breaks a scan — it just runs slower.
---
 
# 4. Dual-Shell Client (Web vs Desktop)
 
VAJRA ships in two synchronized editions that share the same visual identity (a pure black `#000000` theme), full-window drag-and-drop ingestion, and the same `Alt+N` cross-platform hotkey:
 
```text
               ┌────────────────────────────────────────────────────────┐
               │              VAJRA Entry Point & Launcher              │
               │  Web: https://Aravkataria.github.io/VAJRA/             │
               │  Native Desktop: VAJRA (Tauri v2 + vajra-core)         │
               │  CLI: vajra scan <path> / vajra --web                  │
               └──────────────────────────┬─────────────────────────────┘
                                          │
        ┌─────────────────────────────────┴─────────────────────────────────┐
        ▼                                                                   ▼
┌───────────────────────────────┐                   ┌───────────────────────────────┐
│     Web Edition (docs/)       │                   │    Tauri v2 Desktop / CLI     │
│  - 100% In-Browser AST Engine │                   │  - Featherweight Native Shell │
│  - Client-side JSZip Engine   │                   │  - In-Process vajra-core IPC  │
│  - Zero Server Infrastructure │                   │  - Zero Python Runtime Needed │
└───────────────────────────────┘                   └───────────────────────────────┘
```
 
### Edition comparison
 
| Feature / Capability | 🌐 Web Edition (`docs/index.html`) | 🖥️ Tauri v2 Desktop App (`src-tauri/`) |
| :--- | :--- | :--- |
| Packaging & Format | Zero install — 100% client-side WebAssembly/JS on GitHub Pages | Native installer (Windows NSIS `.exe`, macOS `.dmg`, Linux `.AppImage`) |
| Runtime Footprint | Browser memory only | Sub-200 ms startup, ~10 MB installer, ~25 MB idle RAM |
| Dependencies | None (any standard browser) | Zero Python required — standalone native binary |
| Drag & Drop | Full-window file, folder, and ZIP drop-zone | Direct OS filesystem drag-and-drop + file dialogs |
| Analysis Engine | Client-side AST sink tracer running in browser RAM | In-process multithreaded Rayon engine (`vajra-core`) |
| Repair Synthesis | In-memory minimal defensive transformation engine | Direct Ollama HTTP REST integration + AST rewriter |
| Verification | In-browser syntax, sink-removal, and sentinel proofs | Multi-stage proof matrix (syntax, sinks, sentinels, fuzzing, mutation) |
| Privacy & Security | Code never leaves the visitor's browser; zero telemetry | 100% offline, isolated local storage |
| Clean Output | Direct in-browser `.zip` generation & download | Streaming `.zip` archive & signed JSON/HTML records |
 
> The source draft lists the desktop verification row as a "6-Stage Proof Matrix" while the rest of the document (see Section 6) describes a 7-stage matrix that includes the SMT prover. Left as-is here since I can't tell which count reflects the current codebase — worth reconciling before you publish.
 
---
 
# 5. Complete End-to-End Workflow
 
```text
[1. INGESTION]
  ├─ Clones GitHub repo via API or Git
  ├─ Unpacks ZIP archive into isolated sandbox
  └─ Traverses local project directory
        │
        ▼
[2. AST STATIC ANALYSIS]
  ├─ Parses code into Abstract Syntax Trees (AST)
  ├─ Traces data flows to dangerous sinks (eval, exec, subprocess, pickle, yaml, SQL)
  └─ Generates structured finding records with file, line, and AST node keys
        │
        ▼
[3. DECISION ENGINE]
  ├─ Classifies finding: Deterministic vs Reasoning vs Decline
  ├─ Selects pre-verified defensive transformation template
  └─ Or constructs prompt with AST context for local reasoning model
        │
        ▼
[4. REPAIR SYNTHESIS]
  ├─ Constructs surgical, minimal candidate diff
  ├─ Verifies file integrity and snapshot bounds
  └─ Produces candidate modified file in staging sandbox
        │
        ▼
[5. 7-STAGE INDEPENDENT VERIFICATION]
  ├─ Stage 1: Syntax & AST Structural Integrity Check
  ├─ Stage 2: Static Sink Elimination Re-scan
  ├─ Stage 3: Dynamic Exploit Sentinel PoC Execution
  ├─ Stage 4: Baseline Regression Test Suite Run
  ├─ Stage 5: Boundary Input Fuzzing Campaign
  ├─ Stage 6: Patch Mutation Invariant Verification
  └─ Stage 7: SMT Formal Constraint Prover (Z3 Theorem Proving)
        │
        ▼
[6. ATOMIC APPLICATION & ASSURANCE]
  ├─ Applies verified patch atomically to source files
  ├─ Generates cryptographic Repair Assurance Record
  └─ Packages verified clean project as a downloadable .ZIP archive
```
 
Every stage in this pipeline exists to answer one question in isolation: is this really a bug, is this really the right fix, and is this fix really safe? Splitting the pipeline this way means a failure at any single stage doesn't just get logged — it routes back with concrete feedback so the next repair attempt can actually improve.
 
---
 
# 6. The 7-Stage Independent Verification Matrix
 
Every candidate patch must achieve a full **7/7 PASS** before it's accepted. If any single stage fails, the patch is rejected and sent back to the reasoning engine along with the failure reason, for an iterative retry:
 
```text
Candidate Patch
   │
   ├── [Stage 01] Syntax & AST Check
   │              Validates that modified code parses cleanly with zero syntax or compile errors.
   │
   ├── [Stage 02] Static Sink Re-scan
   │              Re-runs AST analysis to prove the dangerous sink node is completely removed.
   │
   ├── [Stage 03] Dynamic Sentinel PoC
   │              Executes concrete exploit payloads in ephemeral sandboxes to verify neutralization.
   │
   ├── [Stage 04] Baseline Regression Invariant
   │              Runs existing project unit tests to ensure zero functional regressions.
   │
   ├── [Stage 05] Boundary Input Fuzzing
   │              Fuzzes patched functions with edge cases, null bytes, unicode, and large buffers.
   │
   ├── [Stage 06] Patch Mutation Invariant
   │              Mutates the repair AST to prove the verification suite is sensitive (100% kill score).
   │
   └── [Stage 07] SMT Formal Constraint Prover (Z3 Theorem Proving)
                  Mathematically proves that the patch's guard and parameterization conditions
                  render the vulnerability sink condition unsatisfiable (UNSAT) for all inputs X:
                  ∀X: Guard(X) ⟹ ¬VulnerableSink(X)
   │
   ▼
[VERIFIED & APPLIED ATOMICALLY]
```
 
The first six stages are empirical — they run real code against real inputs and watch what happens. The seventh stage is the odd one out and the strongest: instead of testing more inputs, it mathematically proves the guard condition holds for *every possible input*, not just the ones that were tried.
 
---
 
# 7. Universal Multi-Language Code Property Graph (CPG)
 
Located in [`app/analysis/cpg_engine.py`](app/analysis/cpg_engine.py), this engine merges three complementary views of the code — **AST** (syntax), **CFG** (control flow), and **DFG** (data flow) — into a single queryable graph, across:
 
- **Python** (`.py`)
- **JavaScript & TypeScript** (`.js`, `.jsx`, `.ts`, `.tsx`)
- **C & C++** (`.c`, `.cpp`, `.h`, `.hpp`)
- **Rust** (`.rs`)
- **Go** (`.go`)
- **Java** (`.java`)
Merging all three views matters because a vulnerability is rarely visible from syntax alone — you also need to know *what calls what* (control flow) and *where tainted data actually travels* (data flow) to confirm a sink is reachable and exploitable rather than dead code.
 
---
 
# 8. Risk Prioritization & Blast Radius Engine
 
Located in [`app/decision/risk_prioritizer.py`](app/decision/risk_prioritizer.py), VAJRA calculates a multi-factor composite risk score (0.0 to 100.0) for every discovered vulnerability:
 
$$\text{Risk Score} = (35\%\times\text{Severity}) + (25\%\times\text{Exploitability}) + (20\%\times\text{Reachability}) + (10\%\times\text{Git Recency}) + (10\%\times\text{Complexity})$$
 
This weighting means severity alone doesn't drive priority — a critical-severity bug in dead code scores lower than a moderate bug sitting on a hot, frequently-changed, easily reachable path.
 
**Blast radius tiers:**
- `SYSTEM_WIDE` (risk ≥ 85.0) — immediate priority for automated surgical repair.
- `SERVICE` (risk 65.0 – 84.9) — service-level impact.
- `ISOLATED` (risk < 65.0) — contained component risk.
---
 
# 9. Patch Minimality & Complexity Evaluator
 
Located in [`app/repair/minimality_evaluator.py`](app/repair/minimality_evaluator.py), this engine scores candidate patches on how little they disturb the surrounding code:
 
- **Line Delta (ΔLOC)**
- **AST Token Perturbation Distance**
- **Cyclomatic Complexity Delta (ΔCC)**
- **Invasiveness Score (0.0 – 100.0)**
When multiple candidate patches all pass verification, VAJRA doesn't just pick the first one that works — it strictly selects the candidate with the lowest invasiveness score (≤ 35%). The idea is that between two patches that are equally *correct*, the one that changes less is the one less likely to introduce something new.
 
---
 
# 10. Long-Term Adaptive Learning & Outcome Tracking
 
Located in [`app/storage/adaptive_learning.py`](app/storage/adaptive_learning.py):
 
- **Persistent Knowledge Graph** (`.vajra/knowledge_graph.json`) — automatically remembers verified fixes across every repository scan, so lessons learned on one codebase carry over to the next.
- **0 ms Fast-Path Retrieval** — when an identical AST sink shows up again, in any project, VAJRA retrieves the already-proven remediation pattern instantly instead of re-reasoning from scratch.
- **Sovereign Fine-Tuning Pipeline** (`scripts/fine_tune_repairer.py`) — exports verified instruction pairs, `(Evidence, Intent) -> Verified Patch`, into standard JSONL format for offline LoRA fine-tuning, so the repair model can eventually be tuned on your own verified fix history.
---
 
# 11. Empirical Benchmark Telemetry & Visualizer
 
VAJRA includes an empirical evaluation suite tested across 50 real-world CWE fixtures:
 
```powershell
py -m tests.benchmark_suite
```
 
### Empirical evaluation scorecard
 
| Metric | Result | Target Benchmark |
| :--- | :--- | :--- |
| Vulnerability Discovery Rate | 98.0% (49 / 50 fixtures) | > 90% |
| Verified Repair Rate | 100.0% of confirmed findings | > 80% |
| Zero-Regression Invariant | 100.0% (0 broken baselines) | 100% |
| Adversarial Mutation Kill Score | 100.0% (3/3 mutants caught) | > 90% |
| Fast-Path LLM Avoidance | 59.2% resolved via AST engine alone | > 50% |
| Total Benchmark Execution Time | < 4.9 seconds (~98 ms / fixture) | < 30 s |
 
The "Fast-Path LLM Avoidance" number is arguably the most telling one here: it means well over half of confirmed findings never needed a model call at all — they were resolved deterministically, which is faster, cheaper, and removes an entire class of hallucination risk.
 
---
 
# 12. Supported Vulnerabilities & Repair Transformation Catalog
 
VAJRA includes specialized deterministic and reasoning repairers for the major vulnerability classes below.
 
### 1. Command Injection (`CWE-78` / `CWE-94`)
- **Vulnerable code:**
```python
  # Vulnerable: Arbitrary expression evaluation
  result = eval(user_input)
 
  # Vulnerable: Shell command injection
  os.system("echo " + user_input)
  subprocess.call(user_cmd, shell=True)
```
- **VAJRA's minimal repair:**
```python
  # Repaired: Literal AST evaluation
  import ast
  result = ast.literal_eval(user_input)
 
  # Repaired: Shell-free parameter list execution
  import subprocess, shlex
  subprocess.run(shlex.split(user_cmd), shell=False, check=True, capture_output=True)
```
 
### 2. Insecure Deserialization (`CWE-502`)
- **Vulnerable code:**
```python
  # Vulnerable: Arbitrary Python bytecode execution
  data = pickle.loads(untrusted_bytes)
  config = yaml.load(raw_yaml)
```
- **VAJRA's minimal repair:**
```python
  # Repaired: Safe serialized data formats
  import json
  data = json.loads(untrusted_bytes)
  config = yaml.safe_load(raw_yaml)
```
 
### 3. SQL Injection (`CWE-89`)
- **Vulnerable code:**
```python
  # Vulnerable: Dynamic string concatenation inside query
  cursor.execute(f"SELECT * FROM accounts WHERE user = '{username}'")
  cursor.execute("DELETE FROM sessions WHERE token = '%s'" % token)
```
- **VAJRA's minimal repair:**
```python
  # Repaired: Parameterized SQL statement
  cursor.execute("SELECT * FROM accounts WHERE user = ?", (username,))
  cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
```
 
### 4. Hardcoded Cryptographic Credentials (`CWE-798`)
- **Vulnerable code:**
```python
  # Vulnerable: Static hardcoded secret in repository
  API_KEY = "AKIA1234567890SECRETKEY"
  DATABASE_PASSWORD = "SuperSecretPassword123!"
```
- **VAJRA's minimal repair:**
```python
  # Repaired: Environment variable extraction
  import os
  API_KEY = os.environ.get("API_KEY", "")
  DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
```
 
### 5. Path Traversal (`CWE-22`)
- **Vulnerable code:**
```python
  # Vulnerable: Unvalidated filesystem path
  with open("/var/data/" + filename, "r") as f:
      content = f.read()
```
- **VAJRA's minimal repair:**
```python
  # Repaired: Path containment check
  from pathlib import Path
  base = Path("/var/data").resolve()
  target = (base / filename).resolve()
  if not target.is_relative_to(base):
      raise PermissionError("Access denied: path traversal attempt")
  with open(target, "r") as f:
      content = f.read()
```
 
---
 
# 13. Decision Engine & Repair Routing
 
The Decision Engine routes every confirmed finding to the repair strategy best suited to it:
 
```text
                     EVIDENCE AGGREGATOR
                             │
                             ▼
                      DECISION ENGINE
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
     [DETERMINISTIC]    [REASONING]       [DECLINE]
    Known safe fix     Contextual fix    Cannot safely
    pattern (<5ms)     via Local LLM     repair (Logs)
```
 
1. **Deterministic Fast Path** — when a context-free defensive fix already exists (e.g. `yaml.load` → `yaml.safe_load`), VAJRA generates and verifies the fix in under 5 ms with zero AI inference cost.
2. **Context-Aware Reasoning Path** — for complex, multi-line logic, VAJRA extracts the relevant AST context and prompts a local reasoning model (Ollama `qwen2.5-coder`) with iterative verification feedback loops.
3. **Structured Decline** — if a fix would alter the program's intended architecture, or the surrounding context isn't clear enough to repair safely, VAJRA logs a structured non-repair reason rather than gambling on a speculative patch.
---
 
# 14. Universal Bootstrapper & Self-Updating Engine
 
VAJRA includes zero-friction installation scripts for every major operating system:
 
```text
               ┌────────────────────────────────────────────────────────┐
               │              Universal Installation Core               │
               │  - Auto-provisions ~/.vajra isolated venv              │
               │  - Adds ~/.local/bin/vajra or .vajra\bin to PATH       │
               │  - Creates Desktop & Start Menu / Applications entry   │
               └──────────────────────────┬─────────────────────────────┘
                                          │
        ┌─────────────────────────────────┼─────────────────────────────────┐
        ▼                                 ▼                                 ▼
[macOS: install.sh]              [Linux: install.sh]             [Windows: install.ps1]
~/Applications/VAJRA.app         ~/.local/share/applications/    Desktop VAJRA.lnk
```
 
### Self-updating engine (`app/launcher.py`)
 
- Every time `vajra` is launched, it quietly queries the GitHub Releases API in the background.
- If a newer version is available, it downloads the update and atomically replaces the application files — without touching the existing virtual environment — then restarts into the updated version.
- Manual updates can also be triggered any time with `vajra update`.
---
 
# 15. Repository Structure
 
```text
VAJRA/
├── docs/                             # Standalone Serverless Web Edition (GitHub Pages)
│   └── index.html                    # 100% Client-side AST analysis & drag-drop UI
│
├── crates/vajra-core/                # High-Performance Multithreaded Rust Engine
│   ├── Cargo.toml                    # Rust crate definition with Rayon & Serde
│   └── src/
│       ├── lib.rs                    # Crate exports
│       ├── main.rs                   # Native CLI interface
│       ├── scanner.rs                # Multi-threaded Rayon AST sink scanner
│       ├── mutation.rs               # In-memory adversarial patch mutator
│       ├── fuzzer.rs                 # Boundary fuzz corpus synthesizer
│       ├── reachability.rs           # Call-graph & import reachability indexer
│       └── git_history.rs            # Native git blame & intent indexer
│
├── scripts/                          # Universal Bootstrappers & Installers
│   ├── install.sh                    # macOS & Linux 1-line bootstrapper
│   ├── install.ps1                   # Windows PowerShell 1-line bootstrapper
│   └── fine_tune_repairer.py         # LoRA dataset exporter & training pipeline
│
├── src-tauri/                        # Tauri v2 Native Desktop Shell & Installers
│   ├── Cargo.toml                    # Desktop wrapper dependencies & vajra-core linkage
│   ├── tauri.conf.json               # NSIS, DMG, AppImage configuration & capabilities
│   ├── icons/                        # Complete multi-resolution application icon assets
│   └── src/                          # Tauri builder & in-process IPC command handlers
│
├── app/                              # Core Server & Python Tooling Engine
│   ├── launcher.py                   # Cross-platform CLI & headless scanner
│   ├── desktop_app.py                # Desktop application bridge
│   ├── api.py                        # FastAPI REST API & local server
│   ├── model_independence.py         # 3-Tier model independence enforcer
│   ├── analysis/                     # AST static analyzers, Multi-Language CPG & Rust adapter
│   ├── decision/                     # Decision Engine & Risk Prioritizer
│   ├── evidence/                     # Evidence aggregator & schema
│   ├── repair/                       # Autonomous loop, deterministic repair & Minimality Evaluator
│   ├── report/                       # HTML/JSON Assurance Records & Benchmark Visualizer
│   ├── repository/                   # Workspace isolation, ZIP extraction, Git manager
│   ├── storage/                      # SQLite persistence & Adaptive Learning Engine
│   ├── verification/                 # 7-Stage independent verification matrix (SMT + Sandbox)
│   └── dashboard/                    # Chat UI & renderer
│
├── .github/workflows/
│   └── release.yml                   # Automated multi-platform Tauri & Rust CI/CD
│
├── tests/                            # Comprehensive automated test suite
├── requirements.txt                  # Python dependencies
├── pytest.ini                        # Pytest configuration
├── LICENSE                           # Apache 2.0 License
└── README.md                         # Project documentation
```
 
---
 
# 16. Installation & Bootstrapping Guide
 
### Option A — Windows graphical setup wizard (`VAJRA-Setup.exe`)
1. Download **VAJRA-Setup.exe** from [Releases](https://github.com/Aravkataria/VAJRA/releases/latest).
2. Double-click the file to open the native NSIS Setup Wizard.
3. Choose the installation mode (*Anyone who uses this computer* vs *Only for me*), pick a directory, and click **Install**.
4. VAJRA launches immediately, with Start Menu and Desktop shortcuts already created.
### Option B — macOS Apple Silicon disk image (`VAJRA-macOS.dmg`)
1. Download **VAJRA-macOS.dmg** from [Releases](https://github.com/Aravkataria/VAJRA/releases/latest).
2. Double-click the `.dmg` and drag **VAJRA** into your `Applications` folder.
### Option C — Linux universal AppImage (`VAJRA-Linux.AppImage`)
1. Download **VAJRA-Linux.AppImage** from [Releases](https://github.com/Aravkataria/VAJRA/releases/latest).
2. Make it executable: `chmod +x VAJRA-Linux.AppImage`
3. Run it: `./VAJRA-Linux.AppImage`
### Option D — one-line terminal install
- **Windows (PowerShell):**
```powershell
  irm https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.ps1 | iex
```
- **macOS & Linux (Bash):**
```bash
  curl -fsSL https://raw.githubusercontent.com/Aravkataria/VAJRA/main/scripts/install.sh | bash
```
 
### System requirements & hardware matrix
 
**Native Desktop & CLI (`vajra-core` + local AI engine)**
 
| Component | Minimum spec (fast-path & core scanner) | Recommended spec (local AI reasoning models) |
| :--- | :--- | :--- |
| Processor (CPU) | Intel Core i3-4130 / AMD Ryzen 3 1200 / Apple M1 or Intel Mac (or any equivalent or higher benchmarked CPU) | Intel Core i5-8400 or Core Ultra / AMD Ryzen 5 3600 / Apple Silicon M1 (or any equivalent or higher benchmarked CPU) |
| Memory (RAM) | 2 GB RAM (engine uses ~25 MB idle, <100 MB scanning) | 8 GB – 16 GB RAM (for running 3B–7B Ollama models) |
| Disk Storage | 100 MB free space (standalone binary) | 5 GB – 10 GB free space (for local quantized weights) |
| Operating System | Windows 10/11 (64-bit), macOS 10.15+, Linux (Ubuntu/Debian/Fedora) | Windows 11 (64-bit), macOS 13+, Linux (x86_64 / ARM64) |
| GPU / Acceleration | None required (100% CPU execution) | Optional: Apple Silicon GPU / NVIDIA GPU (6 GB+ VRAM) |
| Internet | Zero internet required (100% offline & sovereign) | Zero internet required (100% offline & sovereign) |
 
**Web Edition (100% in-browser & serverless)**
- Supported browsers: Chrome, Safari, Firefox, Edge, Brave — across Windows, macOS, Linux, iOS, and Android.
- Hardware footprint: needs only 1 GB RAM and 0 MB of disk storage — forensic analysis and defensive repair execution run entirely in client-side RAM, with zero installation.
---
 
# 17. Command-Line Interface (CLI) Reference
 
```bash
# 1. Launch Native Desktop App (Default)
vajra
 
# 2. Launch Local Web Dashboard in Browser
vajra --web --port 8000
 
# 3. Headless Terminal Security Scan
vajra scan /path/to/project
 
# 4. Machine-Readable JSON Output
vajra scan /path/to/project --json
 
# 5. Run 50-Fixture Empirical Benchmark Suite
vajra --benchmark
 
# 6. Check and Apply Updates from GitHub
vajra update
```
 
---
 
# 18. REST API Gateway Reference
 
Start the local FastAPI server directly:
 
```bash
uvicorn app.api:app --reload --host 127.0.0.1 --port 8000
```
 
### Endpoints
 
**`GET /health`** — returns system status, active verifiers, and loaded repair models:
```json
{
  "status": "ok",
  "version": "2.4.0",
  "repair_modes": ["DeterministicRepairer", "AIRepairer"],
  "verifiers_ready": 6
}
```
 
**`POST /scan-github`** — clones and scans a public GitHub repository directly.
- Request:
```json
  {
    "url": "https://github.com/Aravkataria/VAJRA-test",
    "branch": "main"
  }
```
- Response: returns a workspace ID, metadata, detected findings, generated diffs, and the verification proof matrix.
**`POST /workspace/{id}/scan`** — executes AST analysis, repair synthesis, and the full verification matrix on an existing workspace.
 
**`GET /workspace/{id}/download-patched`** — streams a verified, clean, patched project archive as a `.zip` download.
 
**`GET /workspace/{id}/report.json`** — returns the complete cryptographic Repair Assurance Record.
 
---
 
# 19. CI/CD Pipeline & GitHub Actions Integration
 
VAJRA can be dropped straight into a GitHub Actions workflow to automatically scan pull requests and generate verified repair diffs.
 
Create `.github/workflows/vajra-scan.yml`:
 
```yaml
name: VAJRA Autonomous Security Scan
 
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
 
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
 
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
 
      - name: Install VAJRA
        run: |
          pip install -r requirements.txt
 
      - name: Run VAJRA Headless Security Scan
        run: |
          python -m app.launcher --scan . --json > vajra-report.json
 
      - name: Upload Security Assurance Report
        uses: actions/upload-artifact@v4
        with:
          name: vajra-assurance-report
          path: vajra-report.json
```
 
---
 
# 20. Testing & Validation Suite
 
VAJRA includes unit, integration, and security verifier test suites, run with pytest:
 
```bash
# Run the complete test suite:
py -m pytest
 
# Run with verbose output and coverage:
py -m pytest -v --tb=short
```
 
### Latest verified test results
 
```text
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\DELL\Desktop\vajra
configfile: pytest.ini
collected 42 items
 
tests/test_assurance_report.py ......                                    [ 14%]
tests/test_async_jobs.py .                                               [ 16%]
tests/test_dashboard.py .                                                [ 19%]
tests/test_fuzzing_verifier.py .                                         [ 21%]
tests/test_model_independence.py ....                                    [ 30%]
tests/test_mutation_verifier.py .                                        [ 33%]
tests/test_regression_verifier.py ..                                     [ 38%]
tests/test_repair_pipeline.py ..                                         [ 42%]
tests/test_repair_retry_loop.py .                                        [ 45%]
tests/test_security_test_verifier.py ...........                         [ 71%]
tests/test_storage_memory.py .                                           [ 73%]
tests/test_syntax_checkers.py ......ssss                                 [ 97%]
tests/test_vector_memory.py .                                            [100%]
 
================== 38 passed, 4 skipped, 1 warning in 10.07s ==================
```
 
---
 
# 21. Configuration & Environment Variables
 
| Variable | Default | Description |
| :--- | :--- | :--- |
| `VAJRA_REPAIR_MODE` | `deterministic` | Repair mode: `deterministic` or `ollama` |
| `OLLAMA_URL` | `http://localhost:11434` | Endpoint for local Ollama server |
| `OLLAMA_REPAIR_MODEL` | `qwen2.5-coder:3b` | LLM model used for reasoning repairs |
| `OLLAMA_REPAIR_NUM_CTX` | `8192` | Model context window size |
| `OLLAMA_REPAIR_NUM_PREDICT` | `4096` | Max tokens generated per repair attempt |
| `VAJRA_API_KEY` | *(none)* | Optional API key for REST gateway protection |
| `VAJRA_REPAIR_DEBUG` | `0` | Set to `1` to output verbose AST and provider traces |
 
---
 
# 22. Security Model & Sandbox Containment
 
Because VAJRA inspects untrusted source code by design, it's built around a few strict defensive constraints:
 
1. **Untrusted codebase input** — every submitted source file, config, and piece of repository metadata is treated as untrusted data, never as trusted instructions.
2. **Prompt injection resistance** — source code is strictly parsed as Abstract Syntax Tree nodes, so an adversarial comment planted in the code can't override the repair rules.
3. **Workspace path containment** — every file operation validates that paths can't escape the sandbox root via `..` traversal.
4. **Execution isolation** — sentinels and tests run inside isolated temporary sandboxes with strict execution timeouts, so a malicious or runaway payload can't affect the host.
---
 
# 23. Evidence Schema & Cryptographic Assurance Record
 
Every completed analysis compiles into a structured, verifiable Assurance Record — the artifact you'd actually hand to an auditor:
 
```json
{
  "target": {
    "repository": "vulnerable-api",
    "commit": "HEAD",
    "timestamp": "2026-08-31T20:00:00Z"
  },
  "findings": [
    {
      "file": "app/routes/auth.py",
      "line": 14,
      "vulnerability_type": "command_injection",
      "severity": "CRITICAL",
      "sink": "os.system"
    }
  ],
  "patches": [
    {
      "file": "app/routes/auth.py",
      "line": 14,
      "diff": "--- a/app/routes/auth.py\n+++ b/app/routes/auth.py\n@@ -14,1 +14,1 @@\n- os.system(cmd)\n+ subprocess.run(shlex.split(cmd), check=True)"
    }
  ],
  "verification_proof_matrix": {
    "syntax_ast_check": "PASS (0ms)",
    "static_sink_rescan": "PASS (0 residual sinks)",
    "exploit_sentinel_poc": "PASS (Neutralized)",
    "baseline_regression": "PASS (0 regressions)",
    "boundary_input_fuzzing": "PASS (Clean)",
    "patch_mutation_invariant": "PASS (100% sensitivity)"
  }
}
```
 
---
 
# 24. Technology Strategy & Scalability
 
- **Zero Inference Fast Paths** — over 80% of standard vulnerability classes (SQLi, command injection flags, unsafe YAML loading, hardcoded credentials) are repaired in under 5 ms with zero GPU overhead.
- **Client-Side Scalability** — the Web Edition offloads all AST computation to visitor client CPUs, which lets it scale to effectively unlimited traffic on GitHub Pages at $0 server cost.
- **Modular Polyglot Path** — the AST architecture is deliberately designed for future extension into deeper JavaScript/TypeScript, Go, and Rust analyzers, beyond the Python-first coverage that exists today.
---
 
# 25. What VAJRA Does Not Claim
 
VAJRA does **not** claim that a passing scan proves a piece of software is 100% defect-free. That would be an overreach no scanner can honestly make.
 
What VAJRA does claim is narrower and, we think, more useful:
 
> **Evidence-based assurance that a specific identified weakness was mitigated under a defined set of independent verification conditions, with zero detected regressions.**
 
---
 
# 26. Research Questions & Evaluation
 
VAJRA is also a vehicle for exploring open questions in autonomous software engineering:
 
1. How much can deterministic AST evidence reduce the reasoning workload actually required from local LLMs?
2. Does a multi-stage verification matrix meaningfully prevent regressions compared to raw generative code models working without one?
3. Can in-browser WebAssembly and client-side AST reasoning eliminate server infrastructure costs entirely for enterprise developer tooling?
---
 
# 27. License
 
VAJRA is open-source software licensed under the [Apache License 2.0](LICENSE).
 
