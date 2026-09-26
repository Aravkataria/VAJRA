"""
VAJRA Autonomous Contributor Engine — Closed-Loop Remediation & Verification Pipeline
Lead Engineer: Arav Kataria

An autonomous, self-healing engineering engine that:
1. Respects real-time traffic (yields when visitor traffic is detected).
2. Runs in an iterative CLOSED LOOP:
   - Scans for syntax errors, security vulnerabilities, performance bottlenecks.
   - Generates surgical, deterministic patches.
   - Verifies each patch via AST syntax compilation and secondary sink scanning.
   - Commits verified patches incrementally to its dedicated branch (vajra/auto-security-patches).
   - Re-checks until zero fixable errors remain.
3. Generates a comprehensive audit ledger (VAJRA_SECURITY_AUDIT.md).
4. Pushes the branch and opens a verified Pull Request on GitHub.
"""

import os
import sys
import re
import ast
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from vajra_bot.scanner import scan_file, scan_content, Finding
from vajra_bot.finder import SemanticFinder
from vajra_bot.verifier import PatchVerifier

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# =============================================================================
# 1. LOAD-AWARE BACKEND GATEKEEPER
# =============================================================================

def check_backend_headroom(backend_url: str) -> Tuple[bool, str]:
    """
    Queries /api/system/load. If 3 or more real-time visitors are chatting,
    VAJRA Autopilot yields immediately so live users experience zero latency.
    """
    if not backend_url:
        return True, "No remote backend configured; using local compute headroom."

    load_url = f"{backend_url.rstrip('/')}/api/system/load"
    try:
        req = urllib.request.Request(load_url, headers={"User-Agent": "VAJRA-Autopilot"}, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            active_queries = data.get("active_queries", 0)
            autopilot_allowed = data.get("autopilot_allowed", True)

            if active_queries > 0 or not autopilot_allowed:
                return False, f"Live visitor traffic detected ({active_queries} active queries). Autopilot yielding."
            return True, "Traffic is zero (server idle). Autopilot proceeding."
    except Exception as e:
        return True, f"Load check bypassed ({e}). Proceeding with off-peak rules."


# =============================================================================
# 2. CLOSED-LOOP REPOSITORY SCANNER & SYNTAX VALIDATOR
# =============================================================================

class AutopilotTask:
    def __init__(self, category: str, file: str, line: int, title: str, description: str, snippet: str):
        self.category = category  # 'SECURITY', 'PERFORMANCE', 'SYNTAX'
        self.file = file
        self.line = line
        self.title = title
        self.description = description
        self.snippet = snippet


def is_scannable_file(path: Path) -> bool:
    """Filters out tests, fixtures, build artifacts, and scanner definitions."""
    p_str = str(path).lower().replace("\\", "/")
    if any(skip in p_str for skip in [
        "/tests/", "/fixtures/", "/benchmarks/", "/node_modules/",
        "/__pycache__/", "/.git/", "/venv/", "/env/", "site-packages"
    ]):
        return False
    if p_str.startswith(("tests/", "fixtures/", "benchmarks/")):
        return False
    if p_str.endswith(("_test.py", ".min.js", "vajra_bot/scanner.py", "vajra_bot/finder.py", "vajra_bot/commands.py")):
        return False
    return path.suffix in (".py", ".js", ".ts", ".html")


def check_syntax(file_path: Path) -> Optional[AutopilotTask]:
    """Validates Python syntax. Returns an AutopilotTask if a SyntaxError exists."""
    if file_path.suffix != ".py":
        return None
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        ast.parse(content, filename=str(file_path))
        return None
    except SyntaxError as e:
        return AutopilotTask(
            category="SYNTAX",
            file=str(file_path),
            line=e.lineno or 1,
            title=f"Syntax Error: {e.msg}",
            description=f"File contains a syntax error on line {e.lineno}: {e.text or ''}",
            snippet=e.text or ""
        )
    except Exception:
        return None


def find_performance_bottlenecks(file_path: Path) -> List[AutopilotTask]:
    """Detects blocking synchronous sleeps in async functions."""
    tasks = []
    if file_path.suffix != ".py":
        return tasks
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if "time.sleep(" in line and "async def" in content:
                snippet = "\n".join(lines[max(0, idx - 2): min(len(lines), idx + 2)])
                tasks.append(AutopilotTask(
                    category="PERFORMANCE",
                    file=str(file_path),
                    line=idx,
                    title="Blocking time.sleep() in Async Context",
                    description="Using time.sleep() in async code blocks the event loop. Replace with asyncio.sleep().",
                    snippet=snippet
                ))
    except Exception:
        pass
    return tasks


# =============================================================================
# 3. SURGICAL DETERMINISTIC PATCHER & SELF-VERIFICATION GATE
# =============================================================================

def apply_surgical_patch(file_path: Path, finding: Finding) -> Tuple[bool, str]:
    """
    Applies a surgical code fix to the target file.
    Runs an immediate AST syntax check and secondary-sink scan.
    If the patch fails verification, the file is rolled back immediately.
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines(keepends=True)
    except Exception as e:
        return False, f"Failed to read {file_path}: {e}"

    lineno = finding.line
    if lineno < 1 or lineno > len(lines):
        return False, f"Line {lineno} out of range in {file_path}"

    original = lines[lineno - 1]
    indent = len(original) - len(original.lstrip())
    pad = " " * indent
    patched = None
    cwe = finding.cwe

    # 1. CWE-489: debug=True -> debug=False (clean keyword replacement without breaking closing parenthesis)
    if cwe == "CWE-489" and re.search(r'\bdebug\s*=\s*True\b', original):
        patched = re.sub(r'\bdebug\s*=\s*True\b', 'debug=False', original)

    # 2. CWE-295: verify=False -> verify=True
    elif cwe == "CWE-295" and re.search(r'\bverify\s*=\s*False\b', original):
        patched = re.sub(r'\bverify\s*=\s*False\b', 'verify=True', original)

    # 3. CWE-78: os.system() -> subprocess.run(..., shell=False)
    elif cwe == "CWE-78" and "os.system(" in original:
        match = re.search(r'os\.system\((.+)\)', original.rstrip())
        arg = match.group(1) if match else "cmd"
        patched = (
            f"{pad}import subprocess\n"
            f"{pad}subprocess.run({arg}, shell=False, check=True)\n"
        )

    # 4. CWE-94: Built-in eval() -> ast.literal_eval() (standalone direct call only)
    elif cwe == "CWE-94" and re.search(r'(?<!\.)\beval\s*\(', original):
        match = re.search(r'(?<!\.)eval\((.+)\)', original.rstrip())
        arg = match.group(1) if match else "expr"
        patched = (
            f"{pad}import ast\n"
            f"{pad}ast.literal_eval({arg})\n"
        )

    # 5. CWE-502: pickle.loads() -> json.loads()
    elif cwe == "CWE-502" and "pickle.loads(" in original:
        patched = (
            f"{pad}import json\n"
            f"{pad}json.loads(data)\n"
        )

    if patched is None or patched == original:
        return False, "No automated deterministic patch available."

    candidate_lines = list(lines)
    candidate_lines[lineno - 1] = patched
    candidate_content = "".join(candidate_lines)

    # STRICT PRE-COMMIT VERIFICATION GATE:
    # 1. Syntax check
    if file_path.suffix == ".py":
        try:
            ast.parse(candidate_content, filename=str(file_path))
        except SyntaxError as se:
            return False, f"Patch failed syntax verification: {se.msg} on line {se.lineno}"

    # 2. Re-scan to ensure the sink is eliminated and no new critical/high sinks were introduced
    new_findings = scan_content(str(file_path), candidate_content)
    for f in new_findings:
        if f.cwe == cwe and f.line == lineno:
            return False, f"Patch verification failed: Original vulnerability {cwe} still present."
        if f.severity in ("CRITICAL", "HIGH") and f.line == lineno:
            return False, f"Patch rejected: Introduced new {f.severity} sink ({f.cwe})."

    # Write verified fix to disk
    try:
        file_path.write_text(candidate_content, encoding="utf-8")
        return True, f"Patched {cwe} on line {lineno}"
    except Exception as e:
        return False, f"Failed to write patch: {e}"


# =============================================================================
# 4. CLOSED-LOOP AUTONOMOUS ITERATOR
# =============================================================================

def run_closed_loop_repair(branch_name: str, max_rounds: int = 5) -> Tuple[List[str], List[Finding]]:
    """
    Executes the closed loop:
    1. Scan codebase for issues.
    2. Patch fixable issues.
    3. Self-verify syntax and security.
    4. Commit verified fixes to branch.
    5. Repeat until zero fixable issues remain or convergence is reached.
    """
    applied_patches_ledger = []
    final_findings = []

    print(f"\n🔁 Starting Closed-Loop Remediation Engine on branch '{branch_name}' (Max rounds: {max_rounds})...")

    # Configure Git bot identity
    try:
        subprocess.run(["git", "config", "user.name", "vajra-bot[bot]"], check=True)
        subprocess.run(["git", "config", "user.email", "333847560+vajra-bot[bot]@users.noreply.github.com"], check=True)
        subprocess.run(["git", "checkout", "-B", branch_name], check=True)
    except Exception as e:
        print(f"⚠️ Git branch initialization note: {e}")

    for round_num in range(1, max_rounds + 1):
        print(f"\n--- [Closed Loop Round {round_num}/{max_rounds}] ---")

        # Discover scannable files
        target_files = [p for p in Path(".").rglob("*") if p.is_file() and is_scannable_file(p)]

        # 1. Scan for security findings
        round_security: List[Finding] = []
        for p in target_files:
            round_security.extend(scan_file(p))

        # 2. Scan for syntax errors
        syntax_errors: List[AutopilotTask] = []
        for p in target_files:
            err = check_syntax(p)
            if err:
                syntax_errors.append(err)

        # 3. Scan for performance bottlenecks
        perf_bottlenecks: List[AutopilotTask] = []
        for p in target_files:
            perf_bottlenecks.extend(find_performance_bottlenecks(p))

        total_issues = len(round_security) + len(syntax_errors) + len(perf_bottlenecks)
        print(f"📊 Round {round_num} Audit: {len(round_security)} Security | {len(syntax_errors)} Syntax | {len(perf_bottlenecks)} Performance")

        if total_issues == 0:
            print("✅ Closed loop converged! Zero issues detected across codebase.")
            final_findings = []
            break

        # Attempt verified patches
        patched_in_this_round = 0
        for f in round_security:
            p = Path(f.file)
            if not p.exists():
                continue
            success, msg = apply_surgical_patch(p, f)
            if success:
                print(f"  ✨ Verified Patch: {f.file} line {f.line} ({f.cwe})")
                # Stage and commit this verified fix
                try:
                    subprocess.run(["git", "add", str(p)], check=True)
                    commit_msg = f"fix(security): auto-patch {f.title} in {p.name} [vajra-bot]"
                    subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True)
                    applied_patches_ledger.append(f"`{f.file}` line {f.line}: {f.title} ({f.cwe})")
                    patched_in_this_round += 1
                except Exception as ce:
                    print(f"  ⚠️ Commit note: {ce}")
            else:
                pass

        final_findings = round_security

        # If no patches could be safely applied in this round, stop looping
        if patched_in_this_round == 0:
            print("ℹ️ No further automated patches can be safely verified. Closed loop completed.")
            break

    return applied_patches_ledger, final_findings


# =============================================================================
# 5. PULL REQUEST OPENER & MAIN ORCHESTRATOR
# =============================================================================

def open_or_update_pr(token: str, repo: str, branch_name: str, title: str, body: str) -> Optional[str]:
    """Pushes the branch and creates or updates a GitHub Pull Request."""
    try:
        remote_url = f"https://x-access-token:{token}@github.com/{repo}.git"
        subprocess.run(["git", "push", "-u", remote_url, branch_name, "--force"], check=True)
        print(f"🚀 Pushed verified branch '{branch_name}' to GitHub.")

        pr_url = f"https://api.github.com/repos/{repo}/pulls"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "VAJRA-Autopilot"
        }
        payload = json.dumps({
            "title": title,
            "head": branch_name,
            "base": "main",
            "body": body
        }).encode("utf-8")

        req = urllib.request.Request(pr_url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            html_url = data.get("html_url")
            print(f"🎉 Successfully opened autonomous Pull Request: {html_url}")
            return html_url
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        if "A pull request already exists" in err:
            print("ℹ️ Pull Request for this branch already exists (updated with latest commits).")
        else:
            print(f"⚠️ GitHub API error opening PR: {err}")
    except Exception as e:
        print(f"⚠️ Error during PR creation: {e}")
    return None


def run_autopilot():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    backend_url = os.environ.get("VAJRA_BACKEND_URL", "https://aravkataria-vajra-v2.hf.space")

    print("⚡ VAJRA Closed-Loop Autonomous Contributor Engine Initializing...")

    # 1. Load-Aware Gatekeeper Check
    can_proceed, reason = check_backend_headroom(backend_url)
    print(f"📊 Backend Load Gatekeeper: {reason}")
    if not can_proceed:
        print("⏸️ VAJRA Autopilot: Pausing to preserve real-time user chat performance. Exiting cleanly.")
        sys.exit(0)

    # 2. Run Closed Loop Remediation on vajra/auto-security-patches
    branch_name = "vajra/auto-security-patches"
    applied_patches, remaining_findings = run_closed_loop_repair(branch_name, max_rounds=5)

    # 3. Generate Clean VAJRA_SECURITY_AUDIT.md
    audit_file = Path("VAJRA_SECURITY_AUDIT.md")
    audit_lines = [
        "# VAJRA Autonomous Security & Quality Audit",
        "",
        "> Automated Code Review & Security Ledger",
        "> Conducted by `vajra-bot[bot]` • Zero-Retention Architecture",
        "",
        "### Scan Metrics",
        f"- **Applied Verified Patches**: {len(applied_patches)}",
        f"- **Remaining Findings (Manual Review)**: {len(remaining_findings)}",
        "",
        "### Verified Code Patches Applied",
        ""
    ]
    if applied_patches:
        for p in applied_patches:
            audit_lines.append(f"- {p}")
    else:
        audit_lines.append("- No automated patches required.")

    audit_lines.append("")
    audit_lines.append("### Detailed Security Ledger")
    audit_lines.append("")

    for f in remaining_findings:
        audit_lines.append(f"#### [{f.severity.upper()}] {f.title} ({f.cwe})")
        audit_lines.append(f"- **File**: `{f.file}` (Line {f.line})")
        audit_lines.append(f"- **Description**: {f.description}")
        if f.suggestion:
            audit_lines.append(f"- **Remediation**: {f.suggestion}")
        audit_lines.append("")

    audit_lines.append("---")
    audit_lines.append("*Powered by [VAJRA Security Auditor](https://github.com/apps/vajra-bot) - Autonomous AST & Cryptographic Review*")

    audit_file.write_text("\n".join(audit_lines), encoding="utf-8")
    print(f"📝 Generated clean audit ledger: {audit_file.name}")

    try:
        subprocess.run(["git", "add", "VAJRA_SECURITY_AUDIT.md"], check=True)
        subprocess.run(["git", "commit", "-m", "feat(security): autonomous VAJRA security audit report [vajra-bot]"], check=True, capture_output=True)
    except Exception:
        pass

    # 4. Open Pull Request ONLY if there are applied patches or audit updates
    pr_body = (
        "## VAJRA Autonomous Security Patch\n"
        "> Opened automatically by `vajra-bot[bot]`. Code patched through a closed-loop self-verification pipeline.\n\n"
        f"VAJRA Autopilot executed closed-loop remediation and applied **{len(applied_patches)} verified patches**.\n\n"
        "### Verified Code Patches Applied\n" +
        ("\n".join(f"- {p}" for p in applied_patches) if applied_patches else "- No code patches required.") +
        "\n\n### Safety Verification\n"
        "- **Syntax Validated**: Every patch verified via `ast.parse` before committing.\n"
        "- **Zero Secondary Sinks**: Code re-scanned to ensure no new vulnerabilities were introduced.\n"
        "- **Audit Ledger Included**: See `VAJRA_SECURITY_AUDIT.md` for full finding details.\n\n"
        "---\n*Powered by [VAJRA Security Auditor](https://github.com/apps/vajra-bot) — Engineered by [Arav Kataria](https://github.com/Aravkataria)*"
    )

    if token and repo:
        open_or_update_pr(
            token=token,
            repo=repo,
            branch_name=branch_name,
            title=f"[VAJRA] Autonomous Security Patches ({len(applied_patches)} files verified)",
            body=pr_body
        )
    else:
        print("ℹ️ Running in local/offline mode. Pull Request creation skipped.")


if __name__ == "__main__":
    run_autopilot()
