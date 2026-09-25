"""
VAJRA Interactive Bot Slash Commands Engine
Handles @vajra interactive PR commands: @vajra fix, @vajra explain, @vajra cvss, @vajra help.
100% Free & Open Source.
Lead Engineer: Arav Kataria
"""

import re
from typing import Dict, Any, List, Optional
from vajra_bot.scanner import Finding


CWE_KNOWLEDGE_BASE = {
    "CWE-89": {
        "title": "SQL Injection (SQLi)",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "SQL Injection occurs when untrusted user input is directly concatenated or interpolated into a dynamic database query string without parameterization.",
        "attack_vector": "Attackers can bypass authentication, read confidential tables, alter or drop databases, and in some configurations execute arbitrary operating system commands.",
        "mitigation": "Always use parameterized query placeholders (e.g., `?` or `%s`) provided by your database driver/ORM. Never format queries using f-strings or raw string concatenation."
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Command injection occurs when an application passes unsanitized input to a system shell interpreter (such as `os.system` or `subprocess` with `shell=True`).",
        "attack_vector": "Attackers append shell metacharacters (`;`, `&&`, `|`, `` ` ``) to execute arbitrary commands with the privileges of the running application process.",
        "mitigation": "Use `subprocess.run([...], shell=False)` with arguments passed as a separated list of strings rather than a concatenated command line string."
    },
    "CWE-94": {
        "title": "Improper Control of Generation of Code (Code Injection)",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Occurs when dynamic code execution functions like `eval()` or `exec()` evaluate untrusted strings containing programming language code.",
        "attack_vector": "Allows attackers to execute arbitrary code directly within the Python runtime environment, leading to full server compromise.",
        "mitigation": "Never invoke `eval()` on user-supplied data. Use safe serialization formats like JSON, or `ast.literal_eval()` when parsing Python literals."
    },
    "CWE-798": {
        "title": "Use of Hard-coded Credentials",
        "cvss": 8.9,
        "severity": "HIGH",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "description": "Hardcoding API keys, tokens, or private keys directly in source code allows anyone with repository access to hijack the credentials.",
        "attack_vector": "Automated threat actor crawlers scan public repositories within seconds of commit to harvest API keys and cloud credentials.",
        "mitigation": "Revoke the exposed key immediately. Store credentials in environment variables (`os.getenv`), GitHub Secrets, or a dedicated key vault."
    },
    "CWE-22": {
        "title": "Path Traversal (Arbitrary File Read/Write)",
        "cvss": 7.5,
        "severity": "HIGH",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Constructing filesystem paths using unvalidated user input containing directory traversal sequences like `../`.",
        "attack_vector": "Attackers can read sensitive files (such as `/etc/passwd` or configuration files) or overwrite critical application code.",
        "mitigation": "Resolve the absolute path with `path.resolve()` and verify that it strictly starts with the designated base directory."
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "Occurs when untrusted data is rendered into the web browser's DOM (e.g., via `innerHTML`) without proper escaping or sanitization.",
        "attack_vector": "Attackers execute malicious JavaScript in victims' browsers, stealing session cookies and triggering unauthorized actions.",
        "mitigation": "Use `textContent` / `innerText` instead of `innerHTML`, or sanitize HTML using a battle-tested library like DOMPurify."
    },
    "CWE-489": {
        "title": "Active Debug Code in Production",
        "cvss": 5.3,
        "severity": "MEDIUM",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Deploying servers with `debug=True` exposes interactive debuggers, memory inspection, and detailed stack traces.",
        "attack_vector": "Attackers use interactive web debuggers to execute arbitrary code or inspect internal configuration variables.",
        "mitigation": "Ensure debug mode is conditionally driven by environment variables (e.g. `DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'`) and disabled in production."
    }
}


def calculate_cvss_summary(findings: List[Finding]) -> Dict[str, Any]:
    """Calculates overall CVSS 3.1 rating based on discovered findings."""
    if not findings:
        return {
            "score": 0.0,
            "severity": "NONE",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "findings_count": 0
        }

    max_score = 0.0
    dominant_cwe = None

    for f in findings:
        info = CWE_KNOWLEDGE_BASE.get(f.cwe)
        score = info["cvss"] if info else 5.0
        if score > max_score:
            max_score = score
            dominant_cwe = f.cwe

    severity = "CRITICAL" if max_score >= 9.0 else ("HIGH" if max_score >= 7.0 else ("MEDIUM" if max_score >= 4.0 else "LOW"))
    vector = CWE_KNOWLEDGE_BASE.get(dominant_cwe, {}).get("vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    return {
        "score": max_score,
        "severity": severity,
        "vector": vector,
        "dominant_cwe": dominant_cwe,
        "findings_count": len(findings)
    }


def handle_bot_command(command_text: str, findings: List[Finding], pr_files_count: int) -> str:
    """
    Parses and executes @vajra interactive slash commands.
    """
    cmd = command_text.strip().lower()

    # 1. @vajra help
    if "help" in cmd:
        return (
            "## ⚡ VAJRA Interactive Commands\n"
            "> **Autonomous AST & AI Security Assistant**\n\n"
            "You can control VAJRA by commenting on this Pull Request with any of these commands:\n\n"
            "| Command | Description |\n"
            "| :--- | :--- |\n"
            "| `@vajra fix` | Generates verified, 1-click patch suggestions for all detected vulnerabilities |\n"
            "| `@vajra cvss` | Calculates official CVSS 3.1 vulnerability metrics and base score |\n"
            "| `@vajra explain <CWE>` | (e.g. `@vajra explain CWE-89`) In-depth threat model & remediation education |\n"
            "| `@vajra review` | Re-runs the full 4-stage AST & neural security audit on this PR |\n"
            "| `@vajra help` | Displays this command guide |\n\n"
            "*Engineered by [Arav Kataria](https://github.com/Aravkataria) • 100% Free & Open Source*"
        )

    # 2. @vajra cvss
    if "cvss" in cmd:
        cvss_data = calculate_cvss_summary(findings)
        score = cvss_data["score"]
        severity = cvss_data["severity"]
        vector = cvss_data["vector"]
        color = "🟢" if score == 0.0 else ("🔴" if score >= 9.0 else ("🟠" if score >= 7.0 else "🟡"))

        return (
            f"## ⚡ VAJRA CVSS 3.1 Vulnerability Assessment\n"
            f"> **Standardized Common Vulnerability Scoring System (CVSS v3.1)**\n\n"
            f"### {color} Base Score: `{score} / 10.0` ({severity})\n\n"
            f"- **CVSS Vector String**: `{vector}`\n"
            f"- **Total Flagged Sinks**: `{cvss_data['findings_count']}`\n"
            f"- **Dominant CWE**: `{cvss_data.get('dominant_cwe', 'None')}`\n\n"
            "| Metric Dimension | Evaluation | Impact Analysis |\n"
            "| :--- | :--- | :--- |\n"
            "| **Attack Vector (AV)** | Network (`AV:N`) | Remotely exploitable without physical or local access |\n"
            "| **Attack Complexity (AC)** | Low (`AC:L`) | No specialized conditions or race conditions needed |\n"
            "| **Privileges Required (PR)** | None (`PR:N`) | Unauthenticated attacker can trigger sink |\n"
            "| **User Interaction (UI)** | None (`UI:N`) | No victim interaction required |\n"
            "| **Scope (S)** | Unchanged (`S:U`) | Exploit confined to target application boundary |\n\n"
            "*💡 Tip: Comment `@vajra fix` to view verified remediation suggestions.*"
        )

    # 3. @vajra explain <CWE>
    match = re.search(r"cwe[-_ ]?(\d+)", cmd)
    if "explain" in cmd and match:
        cwe_key = f"CWE-{match.group(1)}"
        info = CWE_KNOWLEDGE_BASE.get(cwe_key)
        if info:
            return (
                f"## ⚡ VAJRA Deep Dive: {info['title']} ({cwe_key})\n"
                f"> **CVSS Score**: `{info['cvss']} ({info['severity']})` • `{info['vector']}`\n\n"
                f"### 📖 Vulnerability Overview\n{info['description']}\n\n"
                f"### 💥 Threat Model & Exploitation Vectors\n{info['attack_vector']}\n\n"
                f"### 🛡️ Defense-in-Depth Remediation\n{info['mitigation']}\n\n"
                f"---  \n*Audited by VAJRA — Lead Engineer: [Arav Kataria](https://github.com/Aravkataria)*"
            )
        else:
            return (
                f"## ⚡ VAJRA Knowledge Base: {cwe_key}\n\n"
                f"VAJRA actively audits for {cwe_key} sinks in source code.\n"
                f"For full standard definitions, refer to the [MITRE CWE Database for {cwe_key}](https://cwe.mitre.org/data/definitions/{match.group(1)}.html)."
            )

    # 4. @vajra fix
    if "fix" in cmd or "patch" in cmd:
        if not findings:
            return (
                "## ⚡ VAJRA Security Fixer\n\n"
                "🛡️ **No vulnerabilities detected!** Your code is clean and passes all AST security checks. No patches needed."
            )

        lines = [
            "## ⚡ VAJRA Autonomous Fixes & Verified Patches",
            "> **Generated by VAJRA Multi-Stage Remediation Engine**",
            "",
            "Review the verified drop-in patches below:",
            ""
        ]

        for idx, f in enumerate(findings, start=1):
            if f.suggestion:
                lines.append(f"### {idx}. Patch for `{f.file}` (Line {f.line}) — {f.title}")
                lines.append(f"**Target CWE**: `{f.cwe}` (`{f.severity}`)")
                lines.append("```suggestion")
                lines.append(f.suggestion)
                lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append("*💡 To commit any of these suggestions, click **Commit suggestion** directly in GitHub.*")
        return "\n".join(lines)

    # Default fallback
    return (
        "## ⚡ VAJRA Bot\n\n"
        "Command received! Use `@vajra help` to see available commands (`@vajra fix`, `@vajra cvss`, `@vajra explain CWE-XX`, `@vajra review`)."
    )
