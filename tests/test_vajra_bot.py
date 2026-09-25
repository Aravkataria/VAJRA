"""
Unit Tests for VAJRA Security Auditor Bot
Verifies Multi-Stage Pipeline:
- Stage 1: AST & Secret Signatures
- Stage 2: Semantic & Neural Finder
- Stage 3: LLM Remediation
- Stage 4: AST Self-Verification
"""

import pytest
from vajra_bot.scanner import scan_content, Finding
from vajra_bot.finder import SemanticFinder
from vajra_bot.verifier import PatchVerifier
from vajra_bot.remediator import ModelRemediator
from vajra_bot.reviewer import build_audit_summary_markdown


# =============================================================================
# STAGE 1: AST & SECRET SIGNATURE TESTS
# =============================================================================

def test_detects_eval_code_injection():
    code = """
def run_dynamic_calc(user_input):
    return eval(user_input)
"""
    findings = scan_content("calc.py", code)
    assert any(f.cwe == "CWE-94" and f.severity == "CRITICAL" for f in findings)


def test_detects_os_system_command_injection():
    code = """
import os
def ping_host(host):
    os.system("ping -c 1 " + host)
"""
    findings = scan_content("net.py", code)
    assert any(f.cwe == "CWE-78" and f.severity == "CRITICAL" for f in findings)


def test_detects_subprocess_shell_true():
    code = """
import subprocess
def run_cmd(user_cmd):
    subprocess.Popen(f"ls {user_cmd}", shell=True)
"""
    findings = scan_content("runner.py", code)
    assert any(f.cwe == "CWE-78" and f.severity == "HIGH" for f in findings)


def test_detects_sql_injection_ast():
    code = """
def get_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
"""
    findings = scan_content("db.py", code)
    assert any(f.cwe == "CWE-89" and f.severity == "CRITICAL" for f in findings)


def test_safe_parameterized_sql_passes():
    code = """
def get_user(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
"""
    findings = scan_content("db.py", code)
    assert not any(f.cwe == "CWE-89" for f in findings)


def test_detects_pickle_deserialization():
    code = """
import pickle
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)
"""
    findings = scan_content("cache.py", code)
    assert any(f.cwe == "CWE-502" for f in findings)


def test_detects_hardcoded_openai_secret():
    code = 'OPENAI_API_KEY = "sk-1234567890abcdef1234567890abcdef12"'
    findings = scan_content("config.py", code)
    assert any(f.cwe == "CWE-798" for f in findings)


def test_detects_hardcoded_github_pat():
    code = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"'
    findings = scan_content("config.py", code)
    assert any(f.cwe == "CWE-798" for f in findings)


def test_detects_xss_innerhtml_in_javascript():
    code = """
function renderProfile(user) {
    document.getElementById("profile").innerHTML = user.bio;
}
"""
    findings = scan_content("profile.js", code)
    assert any(f.cwe == "CWE-79" for f in findings)


# =============================================================================
# STAGE 2: SEMANTIC & NEURAL FINDER TESTS
# =============================================================================

def test_semantic_finder_detects_debug_mode():
    code = "app.run(host='0.0.0.0', debug=True)"
    findings = SemanticFinder.scan_context("server.py", code)
    assert any(f.cwe == "CWE-489" for f in findings)


def test_semantic_finder_detects_path_traversal():
    code = 'with open(f"/var/data/{user_file}", "r") as f:\n    pass'
    findings = SemanticFinder.scan_context("storage.py", code)
    assert any(f.cwe == "CWE-22" for f in findings)


def test_semantic_finder_detects_broken_hash():
    code = "digest = hashlib.md5(password.encode()).hexdigest()"
    findings = SemanticFinder.scan_context("crypto.py", code)
    assert any(f.cwe == "CWE-328" for f in findings)


# =============================================================================
# STAGE 4: AST SELF-VERIFICATION TESTS
# =============================================================================

def test_patch_verifier_accepts_clean_patch():
    patch = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    is_valid, msg, code = PatchVerifier.verify_patch("db.py", "vulnerable_code", patch, "CWE-89")
    assert is_valid is True
    assert "AST-Verified Safe" in msg
    assert code == patch


def test_patch_verifier_rejects_syntax_error():
    broken_patch = "def broken_func(:\n    pass"
    is_valid, msg, code = PatchVerifier.verify_patch("script.py", "orig", broken_patch, "CWE-89")
    assert is_valid is False
    assert "Syntax verification failed" in msg


def test_patch_verifier_rejects_secondary_sink():
    # Attempting to fix SQLi by using dynamic eval()
    toxic_patch = "safe_query = eval(user_input)"
    is_valid, msg, code = PatchVerifier.verify_patch("db.py", "orig", toxic_patch, "CWE-89")
    assert is_valid is False
    assert "Introduced new CRITICAL sink" in msg


def test_model_remediator_fallback_to_verified_template():
    remediator = ModelRemediator()
    # Force offline fallback
    remediator.groq_key = None
    remediator.gemini_key = None
    remediator.vajra_url = ""

    fallback = "cursor.execute('SELECT * FROM t WHERE id = %s', (id,))"
    patch, verified = remediator.generate_verified_remediation("db.py", 10, "bad_code", "CWE-89", fallback)
    assert patch == fallback
    assert verified is True


# =============================================================================
# PR REVIEW FORMATTING TESTS
# =============================================================================

def test_build_audit_summary_markdown_passed():
    summary = build_audit_summary_markdown([], files_scanned_count=3)
    assert "ALL CHECKS PASSED" in summary
    assert "No critical AST sinks" in summary
    assert "100/100" in summary


def test_build_audit_summary_markdown_critical():
    finding = Finding(
        file="auth.py",
        line=42,
        cwe="CWE-89",
        severity="CRITICAL",
        title="SQL Injection Sink",
        description="Dynamic SQL construction detected.",
        suggestion="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    )
    summary = build_audit_summary_markdown([finding], files_scanned_count=1)
    assert "SECURITY ACTION REQUIRED" in summary
    assert "CWE-89" in summary
    assert "auth.py" in summary
    assert "65/100" in summary


# =============================================================================
# INTERACTIVE SLASH COMMANDS TESTS
# =============================================================================

def test_slash_command_help():
    from vajra_bot.commands import handle_bot_command
    reply = handle_bot_command("@vajra help", [], 2)
    assert "VAJRA Interactive Commands" in reply
    assert "@vajra fix" in reply
    assert "@vajra cvss" in reply


def test_slash_command_cvss():
    from vajra_bot.commands import handle_bot_command
    finding = Finding(
        file="db.py",
        line=10,
        cwe="CWE-89",
        severity="CRITICAL",
        title="SQL Injection",
        description="Dynamic SQL"
    )
    reply = handle_bot_command("@vajra cvss", [finding], 1)
    assert "CVSS 3.1" in reply
    assert "9.8" in reply
    assert "CRITICAL" in reply


def test_slash_command_explain():
    from vajra_bot.commands import handle_bot_command
    reply = handle_bot_command("@vajra explain CWE-89", [], 1)
    assert "SQL Injection (SQLi)" in reply
    assert "Threat Model" in reply
    assert "parameterized query" in reply.lower()


def test_slash_command_fix():
    from vajra_bot.commands import handle_bot_command
    finding = Finding(
        file="db.py",
        line=10,
        cwe="CWE-89",
        severity="CRITICAL",
        title="SQLi",
        description="SQL",
        suggestion="cursor.execute('SELECT * FROM users WHERE id = %s', (id,))"
    )
    reply = handle_bot_command("@vajra fix", [finding], 1)
    assert "VAJRA Autonomous Fixes" in reply
    assert "cursor.execute" in reply


# =============================================================================
# AUTOPILOT CONTRIBUTOR TESTS
# =============================================================================

def test_autopilot_todo_detection(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("# TODO: optimize memory footprint for large embeddings\ndef hello(): pass", encoding="utf-8")
    from vajra_bot.autopilot import find_unfinished_todos
    todos = find_unfinished_todos(f)
    assert len(todos) == 1
    assert "optimize memory footprint" in todos[0].description


def test_autopilot_perf_detection(tmp_path):
    f = tmp_path / "async_service.py"
    f.write_text("import time\nasync def poll():\n    time.sleep(5)\n", encoding="utf-8")
    from vajra_bot.autopilot import find_performance_opportunities
    perf = find_performance_opportunities(f)
    assert len(perf) == 1
    assert "Blocking sleep" in perf[0].title


def test_autopilot_backend_load_gatekeeper():
    from vajra_bot.autopilot import check_backend_headroom
    # Offline or empty URL allows run
    can_proceed, reason = check_backend_headroom("")
    assert can_proceed is True
    assert "headroom" in reason
