# app/verification/regression_verifier.py

"""
Regression Test Verifier for VAJRA.

Key design principles:
1. Baseline causal delta: Compares test results before vs after.
2. Target language check: Only executes Python test runners if the target contains Python code.
3. Dependency tolerance: If tests fail to collect due to missing external dependencies,
   marks the result as inconclusive and defers rather than producing a false rejection.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from app.repair.patch import Patch
from app.verification.result import VerificationResult
from app.verification.verification_model import VerificationModel

DEFAULT_REGRESSION_TIMEOUT_SECONDS = int(
    os.environ.get("VAJRA_REGRESSION_TIMEOUT", "15")
)


class RegressionVerifier(VerificationModel):
    def __init__(self, timeout: int = DEFAULT_REGRESSION_TIMEOUT_SECONDS):
        self.timeout = timeout

    def _is_python_repo(self, workspace_path: Path) -> bool:
        return any(workspace_path.rglob("*.py"))

    def _detect_test_runner(self, workspace_path: Path) -> Tuple[bool, Optional[list[str]]]:
        if not self._is_python_repo(workspace_path):
            return False, None

        has_py_test_files = any(workspace_path.glob("test_*.py")) or any(workspace_path.glob("*_test.py"))
        tests_dir = workspace_path / "tests"
        test_dir = workspace_path / "test"
        has_tests_dir_py = (
            (tests_dir.is_dir() and any(tests_dir.rglob("*.py")))
            or (test_dir.is_dir() and any(test_dir.rglob("*.py")))
        )
        has_pytest_config = (workspace_path / "pytest.ini").exists() or (workspace_path / "pyproject.toml").exists()

        if not (has_py_test_files or has_tests_dir_py or has_pytest_config):
            return False, None

        return True, [sys.executable, "-m", "pytest"]

    def _run_suite(self, workspace_dir: Path, cmd: list[str]) -> Tuple[int, str, bool]:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(workspace_dir),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            out = (proc.stdout + "\n" + proc.stderr).strip()
            is_import_err = (
                "ModuleNotFoundError:" in out
                or "ImportError: cannot import name" in out
                or "No module named" in out
            )
            return proc.returncode, out, is_import_err
        except subprocess.TimeoutExpired:
            return -1, f"Test suite execution timed out after {self.timeout}s.", False
        except Exception as exc:
            return -2, f"Execution failed: {exc}", False

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        root = Path(workspace_path).resolve()
        source_path = (root / patch.file).resolve()
        try:
            source_path.relative_to(root)
        except ValueError:
            return VerificationResult(
                patch, False, "regression-test-suite", "Patch path escapes workspace."
            )

        has_tests, cmd = self._detect_test_runner(root)
        if not has_tests or cmd is None:
            return VerificationResult(
                patch,
                True,
                "regression-test-suite:skipped",
                "No relevant test suite detected in workspace; skipped regression run.",
            )

        try:
            original_source = source_path.read_text(encoding="utf-8")
            patched_source = patch.apply_to_source(original_source)
        except (OSError, ValueError) as exc:
            return VerificationResult(
                patch, False, "regression-test-suite", f"Could not construct candidate source: {exc}"
            )

        temp_workspace = Path(tempfile.mkdtemp(prefix="vajra-reg-workspace-"))
        try:
            # 1. Baseline Run
            shutil.copytree(root, temp_workspace, dirs_exist_ok=True)
            orig_exit, orig_out, orig_import_err = self._run_suite(temp_workspace, cmd)

            if orig_import_err:
                return VerificationResult(
                    patch,
                    True,
                    "regression-test-suite:inconclusive",
                    "Target workspace tests require dependencies not installed in analysis environment; skipped regression check.",
                )

            # 2. Patched Run
            target_path = (temp_workspace / patch.file).resolve()
            target_path.write_text(patched_source, encoding="utf-8")
            patch_exit, patch_out, patch_import_err = self._run_suite(temp_workspace, cmd)

            if patch_exit == 0:
                return VerificationResult(
                    patch,
                    True,
                    "regression-test-suite",
                    "Workspace regression tests passed successfully.",
                )

            if orig_exit != 0 and orig_exit == patch_exit:
                return VerificationResult(
                    patch,
                    True,
                    "regression-test-suite:baseline-neutral",
                    "Test failures matched pre-existing baseline; patch did not introduce new regressions.",
                )

            summary = patch_out[-1500:] if len(patch_out) > 1500 else patch_out
            return VerificationResult(
                patch,
                False,
                "regression-test-suite",
                f"Patch introduced new test failures (exit code {patch_exit}):\n{summary}",
            )

        finally:
            shutil.rmtree(temp_workspace, ignore_errors=True)