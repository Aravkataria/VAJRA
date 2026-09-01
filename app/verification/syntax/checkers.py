# app/verification/syntax/checkers.py

"""
Per-language syntax checkers for VAJRA's SyntaxVerifier.

Each checker takes the complete candidate source (as a string) and the
patch's filename, and returns (ok: bool, message: str) -- or None if
this environment can't actually check that language right now (a
required tool isn't installed). A missing checker is not treated as a
failure: SyntaxVerifier defers on it, the same way SecurityTestVerifier
defers when it has no exploit-PoC template for a finding type.

This module does not try to cover "every language" -- doing that for
real means shelling out to that language's own compiler or parser,
which may or may not be installed wherever VAJRA happens to be running.
What's registered here are the languages this environment can actually
check today. Adding another one is just another function plus a line
in CHECKERS -- match the (source, filename) -> Optional[(bool, str)]
shape and it plugs in the same way.
"""

import ast
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

CheckResult = Tuple[bool, str]
Checker = Callable[[str, str], Optional[CheckResult]]


def check_python(source: str, filename: str) -> CheckResult:
    try:
        ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return False, f"Patch introduces a syntax error: {exc.msg} (line {exc.lineno})."
    return True, "Valid Python syntax."


def check_json(source: str, filename: str) -> CheckResult:
    try:
        json.loads(source)
    except json.JSONDecodeError as exc:
        return False, f"Patch introduces invalid JSON: {exc.msg} (line {exc.lineno})."
    return True, "Valid JSON syntax."


def check_yaml(source: str, filename: str) -> Optional[CheckResult]:
    try:
        import yaml
    except ImportError:
        return None  # PyYAML not installed -- can't check, don't guess.

    try:
        # SafeLoader is enough to confirm the document parses; whether a
        # yaml.load() call elsewhere in the code uses a safe loader is a
        # security question SecurityTestVerifier/StaticRescanVerifier own,
        # not a syntax one.
        yaml.load(source, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        return False, f"Patch introduces invalid YAML: {exc}"
    return True, "Valid YAML syntax."


def _run_external(command: list, source: str, suffix: str, timeout: int = 5) -> Optional[CheckResult]:
    """Write `source` to a temp file and run an external syntax-check
    command over it. Returns None if the required tool isn't installed,
    so the caller can defer instead of reporting a false failure."""

    tool = command[0]
    if shutil.which(tool) is None:
        return None

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as f:
        f.write(source)
        temp_path = f.name

    try:
        proc = subprocess.run(
            command + [temp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout).strip()
            return False, f"Patch introduces a syntax error ({tool}): {message[:500]}"
        return True, f"Valid syntax (checked with {tool})."
    except subprocess.TimeoutExpired:
        return False, f"Syntax check with {tool} timed out."
    finally:
        Path(temp_path).unlink(missing_ok=True)


def check_javascript(source: str, filename: str) -> Optional[CheckResult]:
    return _run_external(["node", "--check"], source, ".js")


def check_typescript(source: str, filename: str) -> Optional[CheckResult]:
    # `tsc --noEmit` gives a real TypeScript check when available; falling
    # back to `node --check` still catches plain syntax errors (missing
    # brace, bad token) even though it doesn't understand TS-only syntax.
    if shutil.which("tsc"):
        return _run_external(["tsc", "--noEmit"], source, ".ts")
    return _run_external(["node", "--check"], source, ".ts")


def check_shell(source: str, filename: str) -> Optional[CheckResult]:
    return _run_external(["bash", "-n"], source, ".sh")


# Maps app.repository.language.detect_language()'s output to a checker.
CHECKERS: Dict[str, Checker] = {
    "Python": check_python,
    "JSON": check_json,
    "YAML": check_yaml,
    "JavaScript": check_javascript,
    "TypeScript": check_typescript,
    "Shell": check_shell,
}
