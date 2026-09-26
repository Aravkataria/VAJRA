"""
VAJRA Security Scanner & AST Analysis Engine
Autonomous vulnerability detection for GitHub Pull Requests.
Lead Engineer: Arav Kataria
"""

import ast
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

# =============================================================================
# SECRET DETECTION PATTERNS (CWE-798)
# =============================================================================
SECRET_PATTERNS = [
    (
        r"ghp_[a-zA-Z0-9]{36,}",
        "CWE-798",
        "CRITICAL",
        "GitHub Personal Access Token (Legacy) Exposed",
        "Revoke and rotate this token immediately. Use GitHub Secrets instead of hardcoding tokens."
    ),
    (
        r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "CWE-798",
        "CRITICAL",
        "Fine-grained GitHub Personal Access Token Exposed",
        "Revoke and rotate this token immediately. Store sensitive tokens in environment variables or GitHub Secrets."
    ),
    (
        r"AKIA[0-9A-Z]{16}",
        "CWE-798",
        "CRITICAL",
        "AWS Access Key ID Detected",
        "Never commit AWS access keys to code. Use IAM roles or AWS Parameter Store/Secrets Manager."
    ),
    (
        r"sk-[a-zA-Z0-9]{32,}",
        "CWE-798",
        "CRITICAL",
        "OpenAI API Key Detected",
        "Exposing LLM API keys can lead to compute hijacking and unexpected charges. Use environment variables."
    ),
    (
        r"hf_[a-zA-Z0-9]{34,}",
        "CWE-798",
        "CRITICAL",
        "Hugging Face API Token Detected",
        "Exposed Hugging Face tokens allow unauthorized model downloads and compute access. Rotate this token."
    ),
    (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "CWE-798",
        "CRITICAL",
        "Cryptographic Private Key Exposed",
        "Private keys should never be checked into version control. Store in a secure vault."
    ),
    (
        r"(?i)(?:api_key|apikey|secret_key|auth_token|client_secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{24,}['\"]",
        "CWE-798",
        "HIGH",
        "Hardcoded Secret or API Key Assignment",
        "Move static secrets and API credentials to environment variables or secret vaults."
    ),
]

# =============================================================================
# WEB VULNERABILITY PATTERNS (CWE-79 / CWE-95)
# =============================================================================
WEB_PATTERNS = [
    (
        r"\.innerHTML\s*=\s*(?!['\"][^'\"<]*['\"])[a-zA-Z0-9_$.]+",
        "CWE-79",
        "HIGH",
        "Potential Cross-Site Scripting (XSS) via innerHTML",
        "Use textContent, innerText, or sanitize HTML with DOMPurify before assigning to innerHTML."
    ),
    (
        r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
        "CWE-79",
        "MEDIUM",
        "React dangerouslySetInnerHTML Usage",
        "Ensure untrusted user input is passed through an HTML sanitization library before rendering."
    ),
]


class Finding:
    def __init__(
        self,
        file: str,
        line: int,
        cwe: str,
        severity: str,
        title: str,
        description: str,
        suggestion: Optional[str] = None
    ):
        self.file = file
        self.line = line
        self.cwe = cwe
        self.severity = severity
        self.title = title
        self.description = description
        self.suggestion = suggestion

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "cwe": self.cwe,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "suggestion": self.suggestion,
        }


class PythonASTSecurityVisitor(ast.NodeVisitor):
    """
    Traverses Python Abstract Syntax Trees looking for dangerous sinks
    including Command Injection, Code Injection, Insecure Deserialization,
    and SQL Injection.
    """

    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: List[Finding] = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            val_name = ""
            if isinstance(node.func.value, ast.Name):
                val_name = node.func.value.id
            func_name = f"{val_name}.{node.func.attr}" if val_name else node.func.attr

        # 1. CWE-94 / CWE-95: eval() and exec() - Must be a direct built-in call, NOT an attribute method like model.eval()
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                line_no = node.lineno
                self.findings.append(Finding(
                    file=self.filename,
                    line=line_no,
                    cwe="CWE-94",
                    severity="CRITICAL",
                    title="Dynamic Code Execution Sink (eval / exec)",
                    description=(
                        f"Direct invocation of `{node.func.id}()` with dynamic arguments allows arbitrary "
                        "remote code execution (RCE). Use `ast.literal_eval()` or structured parsers."
                    ),
                    suggestion=(
                        "import ast\n"
                        "# Safe replacement:\n"
                        "safe_result = ast.literal_eval(...)"
                    )
                ))

        # 2. CWE-502: pickle.loads()
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"):
            line_no = node.lineno
            self.findings.append(Finding(
                file=self.filename,
                line=line_no,
                cwe="CWE-502",
                severity="HIGH",
                title="Insecure Deserialization via pickle",
                description=(
                    "The `pickle` module is not secure against untrusted data. An attacker can construct "
                    "serialized payloads that execute arbitrary shell commands upon loading. Use JSON, MsgPack, or Protobuf."
                )
            ))

        # 3. CWE-78: Command Injection via os.system or subprocess
        if func_name in ("os.system", "os.popen"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(Finding(
                    file=self.filename,
                    line=node.lineno,
                    cwe="CWE-78",
                    severity="CRITICAL",
                    title="OS Command Injection Sink (os.system)",
                    description=(
                        f"`{func_name}()` runs commands through the system shell. Passing dynamic variables "
                        "allows shell metacharacter injection (e.g. `; rm -rf /`). Use `subprocess.run([...], shell=False)`."
                    ),
                    suggestion="import subprocess\nsubprocess.run(['command', arg1, arg2], check=True)"
                ))

        if func_name in ("subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_output"):
            # Check for shell=True with dynamic arguments
            is_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    is_shell_true = True
                    break

            if is_shell_true and node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(Finding(
                    file=self.filename,
                    line=node.lineno,
                    cwe="CWE-78",
                    severity="HIGH",
                    title="Subprocess Invocation with shell=True",
                    description=(
                        "Invoking subprocesses with `shell=True` exposes the application to command injection. "
                        "Pass an argument list directly with `shell=False`."
                    ),
                    suggestion="subprocess.run(['command', arg], shell=False, check=True)"
                ))

        # 4. CWE-89: SQL Injection via cursor.execute()
        if func_name in ("cursor.execute", "db.execute", "session.execute", "connection.execute"):
            if node.args:
                arg0 = node.args[0]
                is_dangerous_query = False
                if isinstance(arg0, ast.JoinedStr):  # f"SELECT ... {user_input}"
                    is_dangerous_query = True
                elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, (ast.Mod, ast.Add)):  # "SELECT " + var or %
                    is_dangerous_query = True

                if is_dangerous_query:
                    self.findings.append(Finding(
                        file=self.filename,
                        line=node.lineno,
                        cwe="CWE-89",
                        severity="CRITICAL",
                        title="SQL Injection Sink (Dynamic Query Construction)",
                        description=(
                            "SQL queries constructed via f-strings or string concatenation bypass query sanitization. "
                            "Use parameterized query bindings (e.g., `cursor.execute('SELECT * FROM t WHERE id = ?', (id,))`)."
                        ),
                        suggestion="cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
                    ))

        # 5. CWE-489: Active Debug Flag in Production (debug=True)
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.findings.append(Finding(
                    file=self.filename,
                    line=node.lineno,
                    cwe="CWE-489",
                    severity="HIGH",
                    title="Active Debug Flag in Production",
                    description=(
                        f"Function `{func_name}()` called with `debug=True` enables debug mode or devtools in production. "
                        "Set `debug=False` before deploying."
                    ),
                    suggestion="Set debug=False before deploying to production."
                ))
            elif kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.findings.append(Finding(
                    file=self.filename,
                    line=node.lineno,
                    cwe="CWE-295",
                    severity="HIGH",
                    title="TLS Certificate Verification Disabled",
                    description=(
                        f"Call `{func_name}()` disables TLS certificate verification (`verify=False`). "
                        "Remove `verify=False` to prevent man-in-the-middle attacks."
                    ),
                    suggestion="Remove verify=False or set verify=True."
                ))

        self.generic_visit(node)



def scan_content(filename: str, content: str) -> List[Finding]:
    """
    Scans a single file's content using both AST analysis (for Python)
    and regex signature analysis (for secrets and common web sinks).
    """
    fn_normalized = filename.lower().replace("\\", "/")
    # Ignore internal scanner definitions, rules, and intentional test fixtures
    if (fn_normalized.endswith(("vajra_bot/scanner.py", "vajra_bot/finder.py", "vajra_bot/commands.py"))
            or "/tests/" in fn_normalized or fn_normalized.startswith("tests/")
            or "/benchmarks/" in fn_normalized or fn_normalized.startswith("benchmarks/")
            or fn_normalized.endswith(("_test.py", ".min.js"))):
        return []

    findings: List[Finding] = []
    lines = content.splitlines()

    # 1. Regex secret & token scanning
    for line_idx, line in enumerate(lines, start=1):
        # Ignore comments or test mock tokens
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or "mock" in stripped.lower() or "test_" in stripped.lower():
            # Still scan if it looks like an actual live token
            if not ("ghp_" in line or "github_pat_" in line or "sk-" in line or "AKIA" in line):
                continue

        for pattern, cwe, severity, title, desc in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    file=filename,
                    line=line_idx,
                    cwe=cwe,
                    severity=severity,
                    title=title,
                    description=desc
                ))

        # Scan for web patterns if applicable
        if filename.endswith((".js", ".jsx", ".ts", ".tsx", ".html", ".vue")):
            for pattern, cwe, severity, title, desc in WEB_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        file=filename,
                        line=line_idx,
                        cwe=cwe,
                        severity=severity,
                        title=title,
                        description=desc
                    ))

    # 2. Python AST Analysis
    if filename.endswith(".py"):
        try:
            tree = ast.parse(content, filename=filename)
            visitor = PythonASTSecurityVisitor(filename, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            # File might be incomplete or have a syntax error, skip AST
            pass

    return findings


def scan_file(path: Path) -> List[Finding]:
    """Reads and scans a file from disk."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return scan_content(str(path), content)
    except Exception as e:
        print(f"⚠️ Could not read {path}: {e}")
        return []
