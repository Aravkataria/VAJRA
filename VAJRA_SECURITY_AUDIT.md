# ⚡ VAJRA Autonomous Security & Quality Audit

> **Automated Code Review & Security Ledger**  
> *Conducted by `vajra-bot[bot]` • Zero-Retention Architecture*

### 📊 Scan Metrics
- **Security Findings**: 77
- **Performance Opportunities**: 7
- **Unfinished Tasks (TODOs)**: 2

### 🔍 Detailed Findings & Remediations

#### [HIGH] Active Debug Mode Enabled in Production Code (CWE-489)
- **File**: `app/desktop_app.py` (Line 99)
- **Description**: Running with `debug=True` leaks interactive debuggers, stack traces, and environment variables. Set debug=False.
- **Remediation Suggestion**:
```python
debug = False
```

#### [HIGH] Subprocess Invocation with shell=True (CWE-78)
- **File**: `scripts/vajra_agent_cli.py` (Line 65)
- **Description**: Invoking subprocesses with `shell=True` exposes the application to command injection. Pass an argument list directly with `shell=False`.
- **Remediation Suggestion**:
```python
subprocess.run(['command', arg], shell=False, check=True)
```

#### [CRITICAL] OpenAI API Key Detected (CWE-798)
- **File**: `tests/test_vajra_bot.py` (Line 80)
- **Description**: Exposing LLM API keys can lead to compute hijacking and unexpected charges. Use environment variables.

#### [HIGH] Hardcoded Secret or API Key Assignment (CWE-798)
- **File**: `tests/test_vajra_bot.py` (Line 80)
- **Description**: Move static secrets and API credentials to environment variables or secret vaults.

#### [CRITICAL] GitHub Personal Access Token (Legacy) Exposed (CWE-798)
- **File**: `tests/test_vajra_bot.py` (Line 86)
- **Description**: Revoke and rotate this token immediately. Use GitHub Secrets instead of hardcoding tokens.

#### [HIGH] Active Debug Mode Enabled in Production Code (CWE-489)
- **File**: `tests/test_vajra_bot.py` (Line 106)
- **Description**: Running with `debug=True` leaks interactive debuggers, stack traces, and environment variables. Set debug=False.
- **Remediation Suggestion**:
```python
debug = False
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/test_vajra_bot.py` (Line 112)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [MEDIUM] Use of Cryptographically Broken Hash Algorithm (MD5 / SHA-1) (CWE-328)
- **File**: `tests/test_vajra_bot.py` (Line 118)
- **Description**: MD5 and SHA-1 suffer from known collision vulnerabilities. Use SHA-256, SHA-512, or BLAKE2 for security hashing.
- **Remediation Suggestion**:
```python
import hashlib
hashlib.sha256(...)
```

#### [CRITICAL] AWS Access Key ID Detected (CWE-798)
- **File**: `tests/test_security_concurrency.py` (Line 151)
- **Description**: Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager.

#### [CRITICAL] GitHub Personal Access Token (Legacy) Exposed (CWE-798)
- **File**: `tests/test_security_concurrency.py` (Line 153)
- **Description**: Revoke and rotate this token immediately. Use GitHub Secrets instead of hardcoding tokens.

#### [CRITICAL] AWS Access Key ID Detected (CWE-798)
- **File**: `tests/test_security_concurrency.py` (Line 159)
- **Description**: Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager.

#### [CRITICAL] Cryptographic Private Key Exposed (CWE-798)
- **File**: `tests/test_security_concurrency.py` (Line 166)
- **Description**: Private keys should never be checked into version control. Store in a secure vault.

#### [CRITICAL] Hugging Face API Token Detected (CWE-798)
- **File**: `tests/test_security_concurrency.py` (Line 181)
- **Description**: Exposed Hugging Face tokens allow unauthorized model downloads and compute access. Rotate this token.

#### [CRITICAL] AWS Access Key ID Detected (CWE-798)
- **File**: `tests/benchmark_suite.py` (Line 83)
- **Description**: Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager.

#### [CRITICAL] GitHub Personal Access Token (Legacy) Exposed (CWE-798)
- **File**: `tests/benchmark_suite.py` (Line 86)
- **Description**: Revoke and rotate this token immediately. Use GitHub Secrets instead of hardcoding tokens.

#### [HIGH] Hardcoded Secret or API Key Assignment (CWE-798)
- **File**: `tests/benchmark_suite.py` (Line 88)
- **Description**: Move static secrets and API credentials to environment variables or secret vaults.

#### [CRITICAL] Cryptographic Private Key Exposed (CWE-798)
- **File**: `tests/benchmark_suite.py` (Line 90)
- **Description**: Private keys should never be checked into version control. Store in a secure vault.

#### [HIGH] Hardcoded Secret or API Key Assignment (CWE-798)
- **File**: `tests/benchmark_suite.py` (Line 91)
- **Description**: Move static secrets and API credentials to environment variables or secret vaults.

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 71)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 73)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 74)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 75)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 76)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 77)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 78)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 79)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `tests/benchmark_suite.py` (Line 80)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Insecure Deserialization via pickle (CWE-502)
- **File**: `app/test_repository/vulnerable_pickle.py` (Line 13)
- **Description**: The `pickle` module is not secure against untrusted data. An attacker can construct serialized payloads that execute arbitrary shell commands upon loading. Use JSON, MsgPack, or Protobuf.

#### [HIGH] Subprocess Invocation with shell=True (CWE-78)
- **File**: `app/test_repository/test1.py` (Line 4)
- **Description**: Invoking subprocesses with `shell=True` exposes the application to command injection. Pass an argument list directly with `shell=False`.
- **Remediation Suggestion**:
```python
subprocess.run(['command', arg], shell=False, check=True)
```

#### [HIGH] Subprocess Invocation with shell=True (CWE-78)
- **File**: `app/test_repository/vulnerable.py` (Line 11)
- **Description**: Invoking subprocesses with `shell=True` exposes the application to command injection. Pass an argument list directly with `shell=False`.
- **Remediation Suggestion**:
```python
subprocess.run(['command', arg], shell=False, check=True)
```

#### [CRITICAL] Dynamic Code Execution Sink (eval / exec) (CWE-94)
- **File**: `app/test_repository/vulnerable.py` (Line 21)
- **Description**: Direct invocation of `eval()` with dynamic arguments allows arbitrary remote code execution (RCE). Use `ast.literal_eval()` or structured parsers.
- **Remediation Suggestion**:
```python
import ast
# Safe replacement:
safe_result = ast.literal_eval(...)
```

#### [CRITICAL] AWS Access Key ID Detected (CWE-798)
- **File**: `docs/app/index.html` (Line 3793)
- **Description**: Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 4904)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 4942)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 4981)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 5006)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 5008)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 5013)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 5051)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 5133)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 6107)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 6261)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 6280)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/app/index.html` (Line 7059)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [CRITICAL] AWS Access Key ID Detected (CWE-798)
- **File**: `docs/workspace/index.html` (Line 3793)
- **Description**: Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 4904)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 4942)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 4981)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 5006)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 5008)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 5013)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 5051)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 5133)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 6107)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 6261)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 6280)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/workspace/index.html` (Line 7059)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [CRITICAL] AWS Access Key ID Detected (CWE-798)
- **File**: `docs/chatbot/index.html` (Line 3793)
- **Description**: Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 4904)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 4942)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 4981)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 5006)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 5008)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 5013)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 5051)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 5133)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 6107)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 6261)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 6280)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/chatbot/index.html` (Line 7059)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/benchmark/finder/index.html` (Line 864)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Hardcoded Secret or API Key Assignment (CWE-798)
- **File**: `docs/benchmark/patchgenerator/index.html` (Line 891)
- **Description**: Move static secrets and API credentials to environment variables or secret vaults.

#### [HIGH] Potential Cross-Site Scripting (XSS) via innerHTML (CWE-79)
- **File**: `docs/benchmark/patchgenerator/index.html` (Line 898)
- **Description**: Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML.

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `docs/benchmark/patchgenerator/index.html` (Line 890)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [HIGH] Potential Path Traversal / Arbitrary File Access (CWE-22)
- **File**: `kaggle/model1_security_analyst/benchmark_comparative_models.py` (Line 87)
- **Description**: Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.
- **Remediation Suggestion**:
```python
target_path = (BASE_DIR / user_filename).resolve()
if not str(target_path).startswith(str(BASE_DIR)):
    raise PermissionError('Path traversal detected')
```

#### [MEDIUM] Use of Cryptographically Broken Hash Algorithm (MD5 / SHA-1) (CWE-328)
- **File**: `kaggle/model1_security_analyst/benchmark_comparative_models.py` (Line 111)
- **Description**: MD5 and SHA-1 suffer from known collision vulnerabilities. Use SHA-256, SHA-512, or BLAKE2 for security hashing.
- **Remediation Suggestion**:
```python
import hashlib
hashlib.sha256(...)
```

#### [MEDIUM] Use of Cryptographically Broken Hash Algorithm (MD5 / SHA-1) (CWE-328)
- **File**: `kaggle/model1_security_analyst/benchmark_comparative_models.py` (Line 113)
- **Description**: MD5 and SHA-1 suffer from known collision vulnerabilities. Use SHA-256, SHA-512, or BLAKE2 for security hashing.
- **Remediation Suggestion**:
```python
import hashlib
hashlib.sha256(...)
```

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `app/desktop_app.py` (Line 70)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `tests/test_vajra_bot.py` (Line 258)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `tests/test_async_jobs.py` (Line 11)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `tests/test_async_jobs.py` (Line 18)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `tests/test_performance_engine.py` (Line 37)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `vajra_bot/autopilot.py` (Line 120)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [PERFORMANCE] Synchronous Blocking sleep() Detected
- **File**: `vajra_bot/autopilot.py` (Line 127)
- **Details**: Using time.sleep() blocks the entire event loop. Use asyncio.sleep() for non-blocking concurrency.

#### [TODO] Unfinished Task [TODO]: optimize memory footprint for large embeddings\ndef hello():
- **File**: `tests/test_vajra_bot.py` (Line 249)
- **Details**: optimize memory footprint for large embeddings\ndef hello(): pass", encoding="utf-8")

#### [TODO] Unfinished Task [TODO]: scan
- **File**: `vajra_bot/autopilot.py` (Line 244)
- **Details**: scan
