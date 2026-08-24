# VAJRA

## Evidence-Driven Autonomous Cyber-Reasoning & Software Repair System

> **Status:** Active research/development prototype — repair and verification foundation implemented; autonomous security-test generation and deeper verification are next.

VAJRA is an evidence-driven cyber-reasoning and software-repair platform designed to connect the complete security-repair lifecycle:

```text
Discover
   ↓
Confirm
   ↓
Understand
   ↓
Retrieve evidence / history
   ↓
Decide
   ↓
Generate repair
   ↓
Generate security tests
   ↓
Verify independently
   ↓
Accept / reject
   ↓
Learn from the result
   ↓
Produce an auditable assurance record
```

The central design principle is that **the reasoning model is not the source of truth**. Specialized analyzers produce evidence, the Decision Engine chooses an appropriate repair strategy, repair models generate candidates, and independent verification determines whether a candidate can be accepted.

---

## Table of Contents

- [1. Project Vision](#1-project-vision)
- [2. Current Status](#2-current-status)
- [3. Current Architecture](#3-current-architecture)
- [4. Current End-to-End Workflow](#4-current-end-to-end-workflow)
- [5. Implemented Components](#5-implemented-components)
- [6. Repair Architecture](#6-repair-architecture)
- [7. AI Repair Behavior](#7-ai-repair-behavior)
- [8. Verification and Patch Safety](#8-verification-and-patch-safety)
- [9. Supported Vulnerability Checks](#9-supported-vulnerability-checks)
- [10. Repository Structure](#10-repository-structure)
- [11. Requirements](#11-requirements)
- [12. Installation](#12-installation)
- [13. Running VAJRA](#13-running-vajra)
- [14. API](#14-api)
- [15. Repair Diagnostics](#15-repair-diagnostics)
- [16. Testing](#16-testing)
- [17. Security Model](#17-security-model)
- [18. What VAJRA Does Not Claim](#18-what-vajra-does-not-claim)
- [19. Current Limitations](#19-current-limitations)
- [20. Development Roadmap](#20-development-roadmap)
- [21. Long-Term Architecture](#21-long-term-architecture)
- [22. Evidence Model](#22-evidence-model)
- [23. Memory and Retrieval](#23-memory-and-retrieval)
- [24. Autonomous Repair Loop](#24-autonomous-repair-loop)
- [25. Repair Assurance Report](#25-repair-assurance-report)
- [26. Technology Strategy](#26-technology-strategy)
- [27. Performance and Scalability](#27-performance-and-scalability)
- [28. Evaluation Plan](#28-evaluation-plan)
- [29. Research Questions](#29-research-questions)
- [30. Expected Final Outcome](#30-expected-final-outcome)
- [31. Important Technical Position](#31-important-technical-position)

---

# 1. Project Vision

VAJRA is intended to go beyond a conventional vulnerability scanner and beyond a system that simply asks an LLM to write a patch.

The long-term system should be able to:

1. Discover potential vulnerabilities.
2. Confirm findings using independent evidence.
3. Understand root cause and affected code paths.
4. Retrieve relevant project, code, Git, vulnerability, patch, and failure history.
5. Prioritize work according to security risk and available evidence.
6. Select deterministic or reasoning-based repair strategies.
7. Generate minimal, project-consistent patches.
8. Generate targeted security tests for the discovered weakness.
9. Run regression, security, static, dynamic, and fuzzing verification.
10. Reject unsafe or ineffective repairs.
11. Store successful and failed repair experience.
12. Produce an auditable Repair Assurance Report.

The final goal is therefore not simply:

> **"Find a vulnerability and generate code."**

It is:

> **"Produce a verified, evidence-supported repair when a safe repair can be established, or provide a structured explanation of why VAJRA cannot safely repair the issue."**

---

# 2. Current Status

The current implementation is an **MVP repair and verification foundation**.

## Implemented now

- ZIP workspace ingestion
- Workspace isolation and path-traversal protection
- Repository discovery
- Basic language detection
- Python AST static analysis
- Structured security findings
- Evidence aggregation
- Deterministic security analysis
- Optional Ollama-based analysis
- Decision Engine
- Deterministic repair model
- Ollama-backed AI repair model
- Multi-line single-file candidate patches
- Complete before/after source snapshots
- Unified diff generation
- Patch integrity validation
- Workspace path containment checks
- Syntax verification
- Static security re-analysis
- Sequential repair/verify/apply processing
- Atomic patch application
- Repair attempt tracking
- Structured model-decline reporting
- Post-repair scanning and finding classification
- Basic automated repair-pipeline tests

## Currently being built next

The next major subsystem is:

> **Security-Test Generation and Security-Test Execution**

That will allow VAJRA to verify not only that a static finding disappeared, but also that the vulnerable behavior is actually prevented while intended behavior remains intact.

---

# 3. Current Architecture

The current implementation is deliberately smaller than the final architecture described in the project design document.

```text
                         USER / CLIENT
                              │
                              ▼
                         FastAPI API
                              │
                              ▼
                     Repository / Workspace
                              │
                              ▼
                       Static Analysis
                              │
                              ▼
                      Evidence Aggregator
                              │
                              ▼
                      Security Analyst
                              │
                              ▼
                       Decision Engine
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
        Deterministic Repair          AI Repairer
                 │                         │
                 └────────────┬────────────┘
                              ▼
                       Candidate Patch
                              │
                              ▼
                       Patch Validation
                              │
                              ▼
                   Independent Verification
                       │              │
                       ▼              ▼
                    Syntax       Static Re-scan
                       │              │
                       └──────┬───────┘
                              ▼
                      Atomic Patch Apply
                              │
                              ▼
                       Post-repair Scan
```

The workspace is **not modified by the reasoning model**.

A candidate must pass the configured validation and verification stages before it is applied.

---

# 4. Current End-to-End Workflow

A scan currently follows this process:

```text
1. Receive workspace
        ↓
2. Discover repository contents
        ↓
3. Run static analysis
        ↓
4. Normalize findings into evidence
        ↓
5. Analyze findings
        ↓
6. Decide deterministic vs reasoning repair
        ↓
7. Attempt deterministic repair
        ↓
8. If needed, attempt AI repair
        ↓
9. Validate candidate patch
        ↓
10. Verify candidate
        ↓
11. Apply only verified patches
        ↓
12. Re-scan workspace
        ↓
13. Classify resolved and remaining findings
```

Repair attempts are processed sequentially so that later repairs operate on the current workspace rather than a stale source snapshot.

---

# 5. Implemented Components

## 5.1 Repository Manager

Responsible for workspace creation, repository discovery, and repository metadata handling.

The repository boundary is treated as untrusted input.

## 5.2 Static Analysis

The current Python analyzer uses the Python AST and detects a small initial set of security patterns.

The analyzer produces structured findings containing information such as:

- file
- line
- function/module
- vulnerability type
- severity
- message

## 5.3 Evidence Aggregator

Normalizes analyzer output into a common evidence structure.

The evidence model is designed to grow later to include:

- static analysis
- dynamic analysis
- fuzzing
- runtime behavior
- history
- dependency information
- reproduction evidence

## 5.4 Security Analyst

The analyst confirms findings and produces structured assessments including:

- confidence
- root cause
- impact
- recommended action
- evidence summary
- limitations

The model is not treated as the final authority.

## 5.5 Decision Engine

The Decision Engine decides whether a deterministic repair is available or whether a reasoning model is required.

Conceptually:

```text
                    Evidence
                       │
                       ▼
                Decision Engine
                 │           │
                 ▼           ▼
          Deterministic   Reasoning
             Repair         Model
```

This provides a fast path for known/simple repairs and a deeper path for ambiguous repairs.

## 5.6 Deterministic Repairer

Provides known security transformations where the intended secure replacement is sufficiently well-defined.

Deterministic repairs are preferred when they are appropriate because they are more predictable and do not consume model inference.

## 5.7 AI Repairer

The AI Repairer is used when the Decision Engine determines that contextual reasoning is required.

The current provider is Ollama.

The model is expected to return a structured repair proposal rather than directly modifying the workspace.

## 5.8 Patch Validator

Candidate patches are validated before they can reach the real workspace.

Checks include:

- path containment
- source snapshot consistency
- patch validity
- syntax validity
- security finding reduction
- protection against introducing additional detected vulnerabilities

## 5.9 Verification

The current verification foundation contains:

- syntax verification
- static re-analysis

The verification architecture is intentionally designed so more independent verification stages can be added later.

## 5.10 Patch Applier

Verified patches are applied atomically.

The applier also enforces workspace path containment so patch paths cannot escape the target workspace.

## 5.11 Post-Repair Scan

After repairs are applied, VAJRA performs another scan and reports:

- resolved findings
- remaining findings
- newly introduced findings
- final repair status

---

# 6. Repair Architecture

The repair system uses a candidate-patch model.

```text
Original Source
      │
      ├───────────────┐
      │               │
      ▼               ▼
Deterministic       AI Repair
   Repair              │
      │                │
      └───────┬────────┘
              ▼
        Candidate Source
              │
              ▼
        Patch Validation
              │
              ▼
         Verification
              │
       ┌──────┴──────┐
       │             │
      FAIL          PASS
       │             │
       ▼             ▼
    Reject          Apply
```

The primary patch representation is based on complete source snapshots rather than a single-line replacement.

This is important because a legitimate repair may need to:

- add an import
- change multiple lines
- add validation
- remove unsafe behavior
- modify a function body
- change a call site

A unified diff is generated for reporting and auditability.

---

# 7. AI Repair Behavior

VAJRA deliberately does **not** force an AI model to produce a patch.

For example:

```python
subprocess.call(user_input, shell=True)
```

does not always have one universally correct replacement. The safe implementation may depend on which commands the application is actually supposed to execute.

Similarly:

```python
eval(user_input)
```

cannot automatically be changed to:

```python
ast.literal_eval(user_input)
```

unless the surrounding application expects Python literal data.

`ast.literal_eval()` is not a drop-in replacement for arbitrary Python expression execution.

Therefore a correct AI outcome may be:

```text
Finding confirmed
      ↓
Reasoning required
      ↓
Insufficient semantic context
      ↓
No patch generated
      ↓
Reason recorded
```

This is considered a **safe failure**, not a system failure.

The API records repair attempts under `repair_attempts` so a model decline is distinguishable from:

- deterministic repair not applicable
- Ollama connection failure
- malformed model response
- invalid candidate patch
- failed verification
- failed application

---

# 8. Verification and Patch Safety

A repair is not considered successful merely because an LLM generated code.

The current acceptance path is:

```text
Candidate
   ↓
Path validation
   ↓
Source snapshot validation
   ↓
Syntax validation
   ↓
Static security re-analysis
   ↓
Accept / reject
```

## Current safety checks

### Workspace containment

Patch paths must remain inside the target workspace.

### Source snapshot integrity

A patch is based on a specific source snapshot. If the file has changed since the patch was generated, the patch is rejected rather than silently applied to different code.

### Syntax validation

Candidate Python must parse successfully before application.

### Vulnerability reduction

The original vulnerability must be reduced or removed by the candidate.

### Additional finding protection

A candidate should not be accepted if it introduces additional detected security problems under the configured static analyzer.

### Atomic application

A verified patch is applied atomically so a failed write does not leave the source file half-modified.

---

# 9. Supported Vulnerability Checks

The current static-analysis foundation includes initial detection support for security patterns such as:

- unsafe `eval()` usage
- command execution with `shell=True`
- unsafe YAML loading
- simple hardcoded credential patterns

These checks are intentionally lightweight in the current phase.

They do **not** constitute complete taint analysis, data-flow analysis, or semantic vulnerability detection.

Future versions should integrate stronger analyzers instead of attempting to reimplement every mature security-analysis capability inside VAJRA.

---

# 10. Repository Structure

The current project is organized approximately as follows:

```text
vajra_fixed/
│
├── app/
│   ├── analysis/
│   │   ├── ai_analyst.py
│   │   ├── analyst.py
│   │   ├── analyst_model.py
│   │   ├── assessment.py
│   │   ├── deterministic_analyst.py
│   │   ├── finding.py
│   │   ├── model_provider.py
│   │   ├── ollama_provider.py
│   │   ├── python_static.py
│   │   ├── test_provider.py
│   │   └── workspace_scan.py
│   │
│   ├── decision/
│   │   ├── decision.py
│   │   └── engine.py
│   │
│   ├── evidence/
│   │   ├── evidence.py
│   │   └── aggregator/
│   │       └── aggregator.py
│   │
│   ├── repair/
│   │   ├── ai_repair.py
│   │   ├── deterministic_repair.py
│   │   ├── model_provider.py
│   │   ├── ollama_repair_provider.py
│   │   ├── patch.py
│   │   ├── patch_applier.py
│   │   ├── repair_model.py
│   │   ├── repairer.py
│   │   └── result.py
│   │
│   ├── repository/
│   │   ├── language.py
│   │   ├── manager.py
│   │   └── metadata.py
│   │
│   ├── verification/
│   │   ├── result.py
│   │   ├── static_rescan_verifier.py
│   │   ├── syntax_verifier.py
│   │   ├── verification_model.py
│   │   └── verifier.py
│   │
│   └── main.py
│
├── tests/
│   └── test_repair_pipeline.py
│
├── app/test_repository/
│   ├── test1.py
│   └── vulnerable.py
│
├── check_repair.py
├── requirements.txt
├── README.md
└── Cyber_Reasoning_System1.pdf
```

---

# 11. Requirements

## Core

- Python 3.10+ recommended
- FastAPI
- Uvicorn
- Pydantic
- Python standard library modules used by the project

## Optional AI repair

- Ollama
- A compatible code-reasoning model

The current development configuration uses:

```text
qwen2.5-coder:3b
```

The model can be changed through environment configuration.

---

# 12. Installation

Create or activate the Python environment used by VAJRA.

Install dependencies:

```powershell
pip install -r requirements.txt
```

For the Ollama repair path, install Ollama separately and make sure the selected model is available.

Example:

```powershell
ollama pull qwen2.5-coder:3b
```

Start Ollama if it is not already running:

```powershell
ollama serve
```

---

# 13. Running VAJRA

## Deterministic mode

```powershell
$env:VAJRA_REPAIR_MODE="deterministic"
uvicorn app.api:app --reload
```

## Ollama mode

```powershell
$env:VAJRA_REPAIR_MODE="ollama"
$env:OLLAMA_REPAIR_MODEL="qwen2.5-coder:3b"
$env:OLLAMA_URL="http://localhost:11434"
$env:OLLAMA_REPAIR_NUM_CTX="8192"
$env:OLLAMA_REPAIR_NUM_PREDICT="4096"
uvicorn app.api:app --reload
```

For development diagnostics:

```powershell
$env:VAJRA_REPAIR_DEBUG="1"
```

When configured correctly, the repair chain should report:

```text
['DeterministicRepairer', 'AIRepairer']
```

and the AI provider should be:

```text
OllamaRepairProvider
```

---

# 14. API

Start the service:

```powershell
uvicorn app.api:app --reload
```

## Health

```text
GET /health
```

The health response should expose the currently loaded repair models.

## Upload

```text
POST /upload
```

The upload endpoint creates an isolated workspace from the submitted repository/archive.

## Scan

```text
POST /workspace/{workspace_id}/scan
```

A scan returns the current evidence, assessment, decision, repair, verification, and post-repair information.

## Delete workspace

```text
DELETE /workspace/{workspace_id}
```

---

# 15. Repair Diagnostics

The repair diagnostic utility is:

```powershell
$env:VAJRA_REPAIR_MODE="ollama"
$env:VAJRA_REPAIR_DEBUG="1"
python check_repair.py <workspace_id> vulnerable.py
```

A repair attempt can produce statuses such as:

```text
DeterministicRepairer → not applicable
AIRepairer            → model declined
AIRepairer            → candidate generated
AIRepairer            → candidate rejected
AIRepairer            → candidate verified
```

This distinction is important when debugging the autonomous repair pipeline.

With debug mode enabled, bounded provider/model diagnostics are printed to the server console.

---

# 16. Testing

## Compile the project

```powershell
python -m compileall app check_repair.py tests
```

## Run automated tests

```powershell
python -m unittest discover -s tests -v
```

The repair foundation currently includes tests covering the AI repair contract and deterministic repair behavior.

## Manual scan test

Start VAJRA and scan a test workspace:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/workspace/<workspace_id>/scan"
```

Inspect:

```text
findings
repair_attempts
patches
verifications
applications
post_repair
repair_result
```

---

# 17. Security Model

VAJRA is itself a security-sensitive system because it processes potentially malicious repositories and may eventually execute their code.

The design therefore follows these principles.

## Untrusted repository input

Treat the following as untrusted:

- source code
- build files
- configuration files
- generated files
- binaries
- test inputs
- repository metadata
- content supplied to the reasoning model

## Model output is untrusted

An AI-generated patch is a **candidate**, not an instruction to modify the real workspace.

## Prompt-injection resistance

Repository source is data. It must not be allowed to override the repair system's instructions merely because a malicious string appears inside source code or comments.

## Workspace containment

Patch paths must remain inside the workspace.

## Verification before application

A candidate is not applied simply because the model generated it.

## Future execution isolation

Dynamic analysis, builds, tests, fuzzing, and target execution should eventually run inside isolated containers or stronger sandbox environments with restricted filesystem and network access.

---

# 18. What VAJRA Does Not Claim

VAJRA does **not** claim that a passing scan or passing repair proves arbitrary software is completely secure.

No finite static analysis, dynamic analysis, fuzzing campaign, regression suite, or model can prove that arbitrary software contains no undiscovered vulnerability.

VAJRA instead aims to provide:

> **Evidence-based assurance that a specific identified weakness was mitigated under a defined set of verification conditions.**

Every future Repair Assurance Report should therefore include verification results and limitations rather than an absolute security claim.

---

# 19. Current Limitations

The current MVP does not yet provide the full capabilities described by the long-term architecture.

Not yet implemented at full production/research depth:

- Change-aware analysis
- Risk-based prioritization
- Full CFG extraction
- Full call-graph analysis
- General taint/data-flow analysis
- Dynamic execution analysis
- Sandboxed target execution
- Automatic security-test generation
- Full regression-test orchestration
- Fuzzing and re-fuzzing
- Coverage comparison
- Patch mutation testing
- Semantic patch minimality scoring
- Code memory
- Patch memory persistence
- Failure memory persistence
- Git-history retrieval
- Vulnerability knowledge retrieval
- Project-specific memory
- PostgreSQL persistence
- Vector retrieval/Qdrant integration
- Distributed worker queues
- Rust performance-critical services
- CI/CD integrations
- IDE integrations
- Frontend/dashboard
- Full Repair Assurance Report generation

These are intentional future stages, not missing prerequisites for the current repair foundation.

---

# 20. Development Roadmap

The roadmap follows the architecture described in the project technical report while keeping implementation incremental.

## Phase 1 — Foundation

**Current foundation**

- Repository Manager
- FastAPI gateway
- Python orchestration
- workspace isolation
- basic repository metadata
- initial job/workspace flow
- repair model interfaces
- verification model interfaces

## Phase 2 — Analysis

Expand the evidence layer with:

- stronger static analysis
- AST extraction
- CFG extraction
- call graphs
- dependency analysis
- taint/data-flow analysis
- dynamic analysis
- fuzzing
- coverage collection

Prefer mature external security-analysis tools where appropriate instead of unnecessarily reimplementing them.

## Phase 3 — Evidence and Memory

Build persistent software-engineering memory:

- Code Memory
- Patch Memory
- Failure Memory
- Git History
- Vulnerability Memory
- Project Memory
- Regression Memory

Introduce structured storage and semantic retrieval.

## Phase 4 — Decision Engine

Expand decisions to include:

- risk scoring
- exploitability
- reachability
- exposure
- recent changes
- historical evidence
- dependency risk
- analyzer confidence
- verification strategy selection
- model-routing decisions

## Phase 5 — Reasoning and Repair

Improve reasoning and patch generation through:

- root-cause reasoning
- relevant-context retrieval
- project conventions
- historical repair retrieval
- multi-file repairs
- patch minimality evaluation
- API/dependency/regression risk analysis

## Phase 6 — Autonomous Verification

This is the **next major implementation stage**.

Build:

1. Security-Test Generator
2. Security-Test Runner
3. Regression-Test Runner
4. Stronger static re-analysis
5. Dynamic verification
6. Re-fuzzing
7. Coverage comparison
8. Verification decision engine

## Phase 7 — Learning

Record and retrieve:

- successful repairs
- failed repairs
- rejected patches
- verification failures
- regression failures
- security-test failures
- project-specific repair patterns

Use this information to improve future repair decisions.

## Phase 8 — Distributed Scaling

Add:

- task/message queues
- independent worker pools
- static-analysis workers
- fuzzing workers
- runtime workers
- reasoning workers
- verification workers
- resource scheduling
- monitoring
- horizontal scaling

---

# 21. Long-Term Architecture

The final architecture is intended to look approximately like this:

```text
                           USER / IDE / CI/CD
                                  │
                                  ▼
                            API GATEWAY
                               FastAPI
                                  │
                                  ▼
                            ORCHESTRATOR
                               Python
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
 Repository Manager        Task Scheduler             PostgreSQL
          │
          ▼
   Change Detection
          │
          ▼
 Risk-Based Prioritization
          │
          ▼
 ┌────────────────────────────────────────────────────────┐
 │                    ANALYSIS LAYER                      │
 │                                                        │
 │ Static │ CFG │ Call Graph │ Taint │ Dependencies       │
 │ Dynamic Analysis │ Fuzzing │ Coverage │ Runtime Data   │
 └──────────────────────────┬─────────────────────────────┘
                            │
                            ▼
                    EVIDENCE AGGREGATOR
                            │
                            ▼
                    RETRIEVAL / MEMORY
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
          ▼                 ▼                  ▼
      Code Memory      Patch Memory       Git History
          │                 │                  │
          └─────────────────┼──────────────────┘
                            ▼
                     DECISION ENGINE
                            │
                  ┌─────────┴─────────┐
                  │                   │
                  ▼                   ▼
          Deterministic Repair   Reasoning Model
                  │                   │
                  └─────────┬─────────┘
                            ▼
                     MINIMAL PATCH
                            │
                            ▼
                SECURITY-TEST GENERATOR
                            │
                            ▼
                  VERIFICATION PIPELINE
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
       ▼                    ▼                    ▼
    Compile             Regression          Security Tests
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                         RE-FUZZ
                            │
                            ▼
                    VERIFICATION ENGINE
                            │
                    ┌───────┴───────┐
                    │               │
                   FAIL            PASS
                    │               │
                    ▼               ▼
              Failure Memory   ASSURANCE REPORT
                    │
                    └──────────► REPAIR EXPERIENCE
```

---

# 22. Evidence Model

VAJRA should eventually pass compact, structured evidence to the Decision Engine and reasoning model rather than unnecessarily supplying an entire repository.

A target evidence object should resemble:

```json
{
  "target": {
    "repository": "example",
    "commit": "abc123"
  },
  "location": {
    "file": "src/parser.cpp",
    "function": "parse_input",
    "line": 143
  },
  "vulnerability": {
    "type": "heap-buffer-overflow",
    "severity": "high"
  },
  "static_analysis": {
    "finding": "...",
    "taint_flow": "...",
    "call_graph": "..."
  },
  "dynamic_analysis": {
    "crash": true,
    "stack_trace": "..."
  },
  "fuzzing": {
    "reproduced": true,
    "coverage": 82.4
  },
  "history": {
    "similar_change_found": true
  }
}
```

The current implementation already uses the same general evidence-oriented direction, while the dynamic, fuzzing, and history fields are future expansion points.

---

# 23. Memory and Retrieval

The long-term VAJRA memory is intended to be software-engineering memory rather than generic document-only RAG.

## Code Memory

Stores or retrieves similar functions, APIs, wrappers, and implementation patterns.

## Patch Memory

Stores successful repairs together with:

- vulnerability
- original code
- patch
- tests
- verification evidence
- final decision

## Failure Memory

Stores rejected repairs and why they failed.

Examples:

```text
Patch compiled but vulnerability remained
Patch caused regression
Security test failed
Patch introduced another finding
Model lacked sufficient context
Project convention was violated
```

## Git History

Provides previous changes and the reason/context surrounding them.

## Vulnerability Memory

Stores remediation patterns and security knowledge.

## Project Memory

Stores project-specific conventions, wrappers, APIs, and architectural constraints.

## Regression Memory

Stores prior tests and outcomes associated with repairs.

The retrieval system should eventually answer questions such as:

- Has this vulnerability been fixed before?
- Has similar code been repaired before?
- What project-specific wrapper should be used?
- Did a previous repair introduce a regression?
- Why was an earlier patch rejected?

---

# 24. Autonomous Repair Loop

The final autonomous loop is intended to be:

```text
DISCOVER
   ↓
CONFIRM
   ↓
UNDERSTAND
   ↓
RETRIEVE
   ↓
DECIDE
   ↓
PATCH
   ↓
GENERATE SECURITY TEST
   ↓
COMPILE / REGRESSION / SECURITY TESTS
   ↓
STATIC RE-ANALYSIS
   ↓
DYNAMIC ANALYSIS
   ↓
RE-FUZZ
   ↓
VERIFY
   ↓
        ┌───────────────┐
        │               │
       FAIL            PASS
        │               │
        ▼               ▼
 Failure Memory   Assurance Report
        │               │
        └───────┐       │
                ▼       │
             REPAIR ◄───┘
            EXPERIENCE
```

A verification failure should eventually return to the Decision Engine rather than simply terminating the entire process.

For example:

```text
Patch A
  ↓
Security test fails
  ↓
Record failure
  ↓
Reason about failure
  ↓
Generate Patch B
  ↓
Verify again
```

This creates the closed repair-learning loop described by the project vision.

---

# 25. Repair Assurance Report

The final system should produce an auditable report containing at least:

- vulnerability
- affected code
- original evidence
- reproduction evidence
- root-cause analysis
- relevant historical context
- repair decision
- repair strategy
- patch
- changed files
- generated security test
- compilation results
- regression results
- security-test results
- static re-analysis
- dynamic-analysis results
- fuzzing/re-fuzzing results
- coverage comparison
- patch minimality metrics
- final verification decision
- confidence
- limitations
- tool/model versions
- execution environment metadata

The report should make it possible to understand **why VAJRA accepted or rejected a repair**.

---

# 26. Technology Strategy

The project is intentionally designed as a modular system.

| Layer | Planned technology | Purpose |
|---|---|---|
| Orchestration | Python | Workflow, Decision Engine, AI integration |
| API | FastAPI / Python | External service interface |
| Reasoning | Local/replaceable model providers | Root-cause reasoning and patch generation |
| Static analysis | Python + mature external tools | Security pattern and program analysis |
| Performance-critical services | Rust | Parsing, indexing, concurrency, high-throughput analysis |
| Relational storage | PostgreSQL | Jobs, vulnerabilities, patches, verification metadata |
| Vector retrieval | Qdrant or equivalent | Semantic retrieval over code, patches, and knowledge |
| Queue/messaging | Redis/RQ, Celery, RabbitMQ, or equivalent | Asynchronous scheduling |
| Isolation | Docker / stronger sandboxing | Safe target execution |
| Fuzzing | AFL++, libFuzzer, honggfuzz, or equivalent | Automated input generation |
| Frontend | React / Next.js | Future dashboard and visualization |

The current implementation does **not** require all of these technologies.

They are part of the long-term architecture.

---

# 27. Performance and Scalability

The long-term performance strategy includes:

- incremental change-aware analysis
- risk-based scheduling
- parallel static analysis
- parallel fuzzing
- parallel dynamic analysis
- caching
- crash deduplication
- selective fuzzing
- compact evidence representation
- retrieval instead of unnecessarily large model contexts
- deterministic fast paths
- deeper reasoning paths only when required
- independently scalable worker pools

The Decision Engine is important to this strategy because expensive model inference should not be used when a deterministic security transformation is sufficient.

---

# 28. Evaluation Plan

VAJRA should eventually be evaluated against:

- representative vulnerable programs
- open-source repositories
- synthetic vulnerability suites
- controlled regression scenarios
- realistic CI/CD changes

Important metrics include:

## Security

- vulnerability discovery rate
- confirmed-vulnerability rate
- false-positive rate
- vulnerability reproduction rate
- patch acceptance rate
- patch correctness
- regression rate
- security-test effectiveness
- re-fuzzing outcomes

## Patch quality

- patch size
- changed-file count
- complexity change
- API changes
- dependency changes
- minimality

## System performance

- time to first confirmed finding
- time to verified repair
- CPU consumption
- memory consumption
- model inference count
- model latency
- cache/retrieval hit rate
- worker throughput
- concurrent-job scalability

## Assurance

- reproducibility
- completeness of evidence
- auditability
- traceability of verification decisions

---

# 29. Research Questions

The project is intended to investigate questions including:

1. How much can external security evidence reduce the reasoning workload required from a small or compressed model?
2. Does retrieval of previous successful and failed repairs improve patch correctness?
3. Can change-aware risk prioritization reduce analysis time without significantly reducing vulnerability discovery?
4. Do automatically generated security tests improve confidence in repair correctness?
5. Does patch minimality reduce regression risk?
6. Can independent evidence fusion reduce false positives compared with a single analyzer?
7. How does the system scale as repository count and concurrent job count increase?
8. Can the Decision Engine reduce model inference cost while maintaining repair quality?

---

# 30. Expected Final Outcome

The intended final outcome is an autonomous security-engineering platform rather than an AI code-generation tool.

Given a repository or CI/CD change, VAJRA should eventually return one of two high-level outcomes:

### Verified repair

A minimal patch is generated and supported by sufficient independent verification evidence.

or:

### Structured non-repair

VAJRA explains why it could not safely repair the issue, including:

- insufficient context
- ambiguous intended behavior
- failed security test
- regression
- static finding remains
- dynamic behavior remains vulnerable
- fuzzing evidence remains
- patch introduced a new issue
- verification failure

This distinction is fundamental to the project's safety model.

---

# 31. Important Technical Position

VAJRA should be presented as providing **evidence-based assurance**, not absolute proof of software safety.

A finite security-analysis pipeline cannot prove that arbitrary software contains no undiscovered vulnerabilities.

The strength of VAJRA should instead come from the combination of:

```text
Independent evidence
        +
Context-aware reasoning
        +
Minimal patching
        +
Security-test generation
        +
Regression testing
        +
Static re-analysis
        +
Dynamic analysis
        +
Re-fuzzing
        +
Failure/repair memory
        +
Complete audit trail
```

An accepted repair should therefore mean:

> **The identified vulnerability was mitigated under the verification conditions recorded by VAJRA, and the system found no tested regression or newly introduced issue within the scope of those checks.**

It should never mean:

> **The software is guaranteed secure.**

---

## Project Definition

> **VAJRA is an evidence-driven autonomous cyber-reasoning and software repair system that combines static and dynamic analysis, fuzzing, dependency analysis, regression testing, retrieval, and repair memory to discover and confirm vulnerabilities. A Decision Engine prioritizes evidence and selects deterministic or model-assisted repair strategies. VAJRA generates minimal patches and targeted security tests, independently verifies candidate repairs, records successful and failed repair experience, and produces an auditable Repair Assurance Report. The architecture uses Python for orchestration and reasoning integration and can use Rust for performance-critical services, enabling a modular path toward high performance, speed, precision, functionality, scalability, and auditability.**

---

## Development Principle

**Build the evidence and verification loop before adding complexity.**

The immediate next development milestone is:

```text
Security-Test Generator
        ↓
Security-Test Runner
        ↓
Regression Verification
        ↓
Stronger Repair Assurance
```

Only after that foundation is reliable should VAJRA move deeper into dynamic analysis, fuzzing, memory/retrieval, distributed workers, and large-scale infrastructure.
