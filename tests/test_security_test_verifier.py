# tests/test_security_test_verifier.py

from pathlib import Path
import tempfile
import shutil
import pytest

from app.repair.patch import Patch
from app.verification.security_test_verifier import SecurityTestVerifier


def _line_of(source: str, needle: str) -> int:
    for i, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return i
    raise ValueError(f"Needle {needle!r} not found in source.")


def test_command_injection_function_level_good_patch_accepted():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
        patched = "import subprocess\ndef run(cmd):\n    subprocess.call([cmd], shell=False)\n"
        (temp_ws / "vuln_cmd.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_cmd.py",
            line=_line_of(original, "shell=True"),
            original_source=original,
            patched_source=patched,
            description="disable shell=True",
            confidence=0.9,
            vulnerability_type="command-injection-risk",
        )
        result = verifier.verify(patch, temp_ws)
        assert result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_command_injection_function_level_sham_patch_rejected():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
        patched = "import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)  # reviewed\n"
        (temp_ws / "vuln_cmd.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_cmd.py",
            line=_line_of(original, "shell=True"),
            original_source=original,
            patched_source=patched,
            description="sham fix: comment only",
            confidence=0.9,
            vulnerability_type="command-injection-risk",
        )
        result = verifier.verify(patch, temp_ws)
        assert not result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsafe_eval_good_patch_accepted():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "def run(expr):\n    return eval(expr)\n"
        patched = "import ast\ndef run(expr):\n    return ast.literal_eval(expr)\n"
        (temp_ws / "vuln_eval.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_eval.py",
            line=_line_of(original, "return eval(expr)"),
            original_source=original,
            patched_source=patched,
            description="use literal_eval",
            confidence=0.9,
            vulnerability_type="unsafe-eval",
        )
        result = verifier.verify(patch, temp_ws)
        assert result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsafe_eval_sham_patch_rejected():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "def run(expr):\n    return eval(expr)\n"
        patched = "def run(expr):\n    return eval(str(expr))\n"
        (temp_ws / "vuln_eval.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_eval.py",
            line=_line_of(original, "return eval(expr)"),
            original_source=original,
            patched_source=patched,
            description="sham: still eval",
            confidence=0.9,
            vulnerability_type="unsafe-eval",
        )
        result = verifier.verify(patch, temp_ws)
        assert not result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsafe_deserialization_yaml_good_patch_accepted():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "import yaml\ndef load_data(raw):\n    return yaml.load(raw, Loader=yaml.Loader)\n"
        patched = "import yaml\ndef load_data(raw):\n    return yaml.safe_load(raw)\n"
        (temp_ws / "vuln_yaml.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_yaml.py",
            line=_line_of(original, "return yaml.load(raw, Loader=yaml.Loader)"),
            original_source=original,
            patched_source=patched,
            description="use safe_load",
            confidence=0.9,
            vulnerability_type="unsafe-deserialization",
        )
        result = verifier.verify(patch, temp_ws)
        assert result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsafe_deserialization_yaml_sham_patch_rejected():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "import yaml\ndef load_data(raw):\n    return yaml.load(raw, Loader=yaml.Loader)\n"
        patched = "import yaml\ndef load_data(raw):\n    return yaml.load(raw, Loader=yaml.UnsafeLoader)\n"
        (temp_ws / "vuln_yaml.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_yaml.py",
            line=_line_of(original, "return yaml.load(raw, Loader=yaml.Loader)"),
            original_source=original,
            patched_source=patched,
            description="sham: still unsafe loader",
            confidence=0.9,
            vulnerability_type="unsafe-deserialization",
        )
        result = verifier.verify(patch, temp_ws)
        assert not result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_hardcoded_credential_good_patch_accepted():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "def connect():\n    password = \"hunter2-supersecret\"\n    return password\n"
        patched = "import os\ndef connect():\n    password = os.environ['DB_PASSWORD']\n    return password\n"
        (temp_ws / "vuln_creds.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_creds.py",
            line=_line_of(original, '    password = "hunter2-supersecret"'),
            original_source=original,
            patched_source=patched,
            description="use environment variable",
            confidence=0.9,
            vulnerability_type="hardcoded-credential",
        )
        result = verifier.verify(patch, temp_ws)
        assert result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_hardcoded_credential_sham_patch_rejected():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "def connect():\n    password = \"hunter2-supersecret\"\n    return password\n"
        patched = "def connect():\n    password = \"hunter2-supersecret\"  # secret\n    return password\n"
        (temp_ws / "vuln_creds.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_creds.py",
            line=_line_of(original, '    password = "hunter2-supersecret"'),
            original_source=original,
            patched_source=patched,
            description="sham: still hardcoded secret",
            confidence=0.9,
            vulnerability_type="hardcoded-credential",
        )
        result = verifier.verify(patch, temp_ws)
        assert not result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsupported_type_is_deferred():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "def foo():\n    return 1\n"
        patched = "def foo():\n    return 2\n"
        (temp_ws / "foo.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="foo.py",
            line=1,
            original_source=original,
            patched_source=patched,
            description="noop",
            confidence=0.5,
            vulnerability_type="unsupported-type-xyz",
        )
        result = verifier.verify(patch, temp_ws)
        assert result.verified
        assert "skipped" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsafe_deserialization_pickle_good_patch_accepted():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "import pickle\ndef load_data(raw):\n    return pickle.loads(raw)\n"
        patched = "import json\ndef load_data(raw):\n    return json.loads(raw.decode('utf-8'))\n"
        (temp_ws / "vuln_pickle.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_pickle.py",
            line=_line_of(original, "return pickle.loads(raw)"),
            original_source=original,
            patched_source=patched,
            description="use safe json.loads instead of pickle",
            confidence=0.95,
            vulnerability_type="unsafe-deserialization",
            call_name="pickle.loads",
        )
        result = verifier.verify(patch, temp_ws)
        assert result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


def test_unsafe_deserialization_pickle_sham_patch_rejected():
    verifier = SecurityTestVerifier(timeout=10)
    temp_ws = Path(tempfile.mkdtemp(prefix="test-sec-ws-"))
    try:
        original = "import pickle\ndef load_data(raw):\n    return pickle.loads(raw)\n"
        patched = "import pickle\ndef load_data(raw):\n    return pickle.loads(raw)  # reviewed\n"
        (temp_ws / "vuln_pickle.py").write_text(original, encoding="utf-8")

        patch = Patch.from_source_change(
            file="vuln_pickle.py",
            line=_line_of(original, "return pickle.loads(raw)"),
            original_source=original,
            patched_source=patched,
            description="sham: comment only, still pickle.loads",
            confidence=0.9,
            vulnerability_type="unsafe-deserialization",
            call_name="pickle.loads",
        )
        result = verifier.verify(patch, temp_ws)
        assert not result.verified
        assert "security-test" in result.method
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)