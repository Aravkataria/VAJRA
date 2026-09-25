"""
Unit Tests for VAJRA Security Auditor Bot
Verifies AST vulnerability detection, secret hunting, and PR review builders.
"""

import pytest
from vajra_bot.scanner import scan_content, Finding
from vajra_bot.reviewer import build_audit_summary_markdown


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
