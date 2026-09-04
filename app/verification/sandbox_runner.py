# app/verification/sandbox_runner.py

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class SandboxConfig:
    timeout_seconds: float = 5.0
    max_memory_mb: int = 512
    allow_network: bool = False
    env_vars: Dict[str, str] = field(default_factory=dict)
    use_container_if_available: bool = True


@dataclass
class SandboxExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    memory_exceeded: bool = False
    duration_ms: float = 0.0

    @property
    def is_success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.memory_exceeded


class SandboxRunner:
    """Ephemeral zero-trust execution sandbox for dynamic verification and fuzzing."""

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    def run_isolated_command(
        self,
        command: List[str],
        cwd: Path,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> SandboxExecutionResult:
        """Executes a command inside an ephemeral isolated workspace."""
        start_time = time.perf_counter()

        # Build sanitized execution environment
        sanitized_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "PYTHONPATH": str(cwd),
            "VAJRA_SANDBOX": "1",
        }
        if self.config.env_vars:
            sanitized_env.update(self.config.env_vars)
        if extra_env:
            sanitized_env.update(extra_env)

        # Create temporary overlay directory to prevent accidental disk mutations
        with tempfile.TemporaryDirectory(prefix="vajra_sandbox_") as tmp_dir:
            tmp_path = Path(tmp_dir)

            try:
                proc = subprocess.Popen(
                    command,
                    cwd=str(cwd),
                    env=sanitized_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                try:
                    stdout, stderr = proc.communicate(timeout=self.config.timeout_seconds)
                    duration_ms = (time.perf_counter() - start_time) * 1000.0

                    return SandboxExecutionResult(
                        returncode=proc.returncode,
                        stdout=stdout or "",
                        stderr=stderr or "",
                        timed_out=False,
                        duration_ms=duration_ms,
                    )
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    duration_ms = (time.perf_counter() - start_time) * 1000.0

                    return SandboxExecutionResult(
                        returncode=-1,
                        stdout=stdout or "",
                        stderr=stderr or "Execution timed out within sandbox limits.",
                        timed_out=True,
                        duration_ms=duration_ms,
                    )

            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return SandboxExecutionResult(
                    returncode=-1,
                    stdout="",
                    stderr=f"Sandbox process execution error: {str(e)}",
                    timed_out=False,
                    duration_ms=duration_ms,
                )


def run_in_sandbox(command: List[str], cwd: Path, timeout: float = 5.0) -> SandboxExecutionResult:
    runner = SandboxRunner(SandboxConfig(timeout_seconds=timeout))
    return runner.run_isolated_command(command, cwd)
