# app/verification/security_test/runner.py

"""
Executes a generated exploit PoC against a target file's source, without
ever touching the real workspace and without trusting the target repo's
own code.

Isolation model: the entire workspace is copied into a fresh temp
directory per run, the file under test is overwritten in that copy with
whichever source snapshot the caller wants to test (original or
patched), and a small generated harness script is dropped alongside it
and executed as a subprocess with a hard timeout. The temp copy and its
marker sentinel are deleted afterward regardless of outcome.

This is deliberately *not* containerized (no Docker) -- it's process +
filesystem isolation only, with a timeout as the baseline safety net
against a PoC harness that hangs. That's a real limitation: a PoC could
still do things a container would have stopped, like making a network
call. It cannot, however, touch the real workspace or the pipeline
process's own state, since it runs in a throwaway directory as its own
subprocess.
"""

import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.verification.security_test.poc_templates import build_poc

DEFAULT_TIMEOUT_SECONDS = 5


@dataclass
class PocRunResult:
    exploited: bool
    timed_out: bool
    error: Optional[str]
    stdout: str
    stderr: str


def _function_harness(module_path: Path, func_name: str, payload: str) -> str:
    """
    Import the target file as a standalone module (module-level code
    outside an `if __name__ == "__main__":` guard runs on import, same as
    a normal import -- nothing extra happens), then call the specific
    vulnerable function directly with the payload as its sole argument.

    This matches this project's demo convention (see
    app/test_repository/vulnerable.py): one function, one
    attacker-controlled positional argument.
    """

    return (
        "import importlib.util\n"
        f"MODULE_PATH = {str(module_path)!r}\n"
        f"FUNC_NAME = {func_name!r}\n"
        f"PAYLOAD = {payload!r}\n"
        "spec = importlib.util.spec_from_file_location('vajra_poc_target', MODULE_PATH)\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "try:\n"
        "    spec.loader.exec_module(module)\n"
        "except Exception:\n"
        "    pass\n"
        "func = getattr(module, FUNC_NAME, None)\n"
        "if func is not None:\n"
        "    try:\n"
        "        func(PAYLOAD)\n"
        "    except Exception:\n"
        "        pass\n"
    )


def _module_harness(module_path: Path) -> str:
    """
    Run the target file directly as __main__, for findings at module
    scope (e.g. app/test_repository/test1.py, which calls input() and
    the dangerous sink at import time rather than inside a function).
    The payload is delivered via stdin by the caller.
    """

    return (
        "import runpy\n"
        f"MODULE_PATH = {str(module_path)!r}\n"
        "try:\n"
        "    runpy.run_path(MODULE_PATH, run_name='__main__')\n"
        "except Exception:\n"
        "    pass\n"
    )


def run_poc(
    *,
    workspace_path: Path,
    relative_file: str,
    source: str,
    function_name: str,
    vulnerability_type: str,
    call_name: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> PocRunResult:
    """
    Run the PoC for `vulnerability_type` against `source` (a specific
    version of `relative_file` -- original or patched), inside an
    isolated copy of `workspace_path`.

    call_name (e.g. "yaml.load", "pickle.loads") is passed through to
    disambiguate finding types that cover more than one sink.
    """

    marker_dir = Path(tempfile.mkdtemp(prefix="vajra-poc-marker-"))
    marker_path = marker_dir / f"pwned-{uuid.uuid4().hex}.marker"

    poc = build_poc(vulnerability_type, marker_path=str(marker_path), call_name=call_name)
    if poc is None:
        shutil.rmtree(marker_dir, ignore_errors=True)
        return PocRunResult(
            exploited=False,
            timed_out=False,
            error=f"No exploit-PoC template for '{vulnerability_type}'.",
            stdout="",
            stderr="",
        )

    if function_name == "module" and poc.delivery == "bytes-arg-only":
        # A bytes payload (e.g. a pickle stream) can't be carried through
        # a text stdin prompt without corrupting it -- there's no
        # reliable module-level delivery path for this payload type, so
        # defer rather than send something that would just fail for the
        # wrong reason.
        shutil.rmtree(marker_dir, ignore_errors=True)
        return PocRunResult(
            exploited=False,
            timed_out=False,
            error=(
                f"'{vulnerability_type}' via {call_name or 'unknown call'} produces a bytes "
                "payload with no reliable stdin delivery for module-level findings."
            ),
            stdout="",
            stderr="",
        )

    temp_workspace = Path(tempfile.mkdtemp(prefix="vajra-poc-workspace-"))
    try:
        shutil.copytree(workspace_path, temp_workspace, dirs_exist_ok=True)

        target_path = (temp_workspace / relative_file).resolve()
        try:
            target_path.relative_to(temp_workspace.resolve())
        except ValueError:
            return PocRunResult(False, False, "Target path escapes workspace copy.", "", "")

        target_path.write_text(source, encoding="utf-8")

        if function_name == "module":
            harness = _module_harness(target_path)
            # Sent a few times in case the target makes more than one
            # sequential input() call before reaching the vulnerable line.
            stdin_data = (poc.payload + "\n") * 5
        else:
            harness = _function_harness(target_path, function_name, poc.payload)
            stdin_data = None

        harness_path = temp_workspace / f"_vajra_poc_{uuid.uuid4().hex}.py"
        harness_path.write_text(harness, encoding="utf-8")

        try:
            proc = subprocess.run(
                [sys.executable, str(harness_path)],
                cwd=str(temp_workspace),
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return PocRunResult(
                exploited=marker_path.exists(),
                timed_out=False,
                error=None,
                stdout=proc.stdout[-2000:],
                stderr=proc.stderr[-2000:],
            )
        except subprocess.TimeoutExpired:
            return PocRunResult(
                exploited=marker_path.exists(),
                timed_out=True,
                error="PoC execution timed out.",
                stdout="",
                stderr="",
            )
        except OSError as exc:
            return PocRunResult(False, False, f"Could not execute PoC: {exc}", "", "")
    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)
        shutil.rmtree(marker_dir, ignore_errors=True)
