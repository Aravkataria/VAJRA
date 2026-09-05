# app/analysis/performance_engine.py

"""
AST-Based Performance & Code Optimization Engine for VAJRA.

Analyzes source code Abstract Syntax Trees to identify algorithmic bottlenecks,
complexity hotspots, and performance anti-patterns:
- Quadratic loop lookups (O(N^2) -> O(1) hash conversions)
- Synchronous blocking calls inside async event loops
- Repeated regex recompilation in loops/functions
- Repeated disk I/O / file opens inside loops
- Quadratic string concatenation in loops
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class OptimizationAdvice:
    file: str
    line: int
    rule_id: str
    category: str
    severity: str  # "high", "medium", "low"
    message: str
    original_snippet: str
    suggested_rewrite: str
    estimated_speedup: str
    function_name: str = "module"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "original_snippet": self.original_snippet,
            "suggested_rewrite": self.suggested_rewrite,
            "estimated_speedup": self.estimated_speedup,
            "function_name": self.function_name,
        }


@dataclass
class PerformanceProfile:
    baseline_duration_ms: float = 0.0
    patched_duration_ms: float = 0.0
    speedup_percentage: float = 0.0
    memory_delta_kb: float = 0.0
    is_faster: bool = False

    @classmethod
    def from_durations(cls, baseline_ms: float, patched_ms: float, memory_delta_kb: float = 0.0) -> PerformanceProfile:
        speedup = 0.0
        if baseline_ms > 0:
            speedup = ((baseline_ms - patched_ms) / baseline_ms) * 100.0
        return cls(
            baseline_duration_ms=round(baseline_ms, 2),
            patched_duration_ms=round(patched_ms, 2),
            speedup_percentage=round(speedup, 1),
            memory_delta_kb=round(memory_delta_kb, 2),
            is_faster=patched_ms < baseline_ms,
        )


class ASTPerformanceVisitor(ast.NodeVisitor):
    """Walks the Python AST to discover performance anti-patterns."""

    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.advice: List[OptimizationAdvice] = []
        self.loop_stack: List[ast.AST] = []
        self.current_function: Optional[ast.FunctionDef | ast.AsyncFunctionDef] = None

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node
        self.generic_visit(node)
        self.current_function = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev = self.current_function
        self.current_function = node
        self.generic_visit(node)
        self.current_function = prev

    def visit_For(self, node: ast.For):
        self.loop_stack.append(node)
        self.generic_visit(node)
        self.loop_stack.pop()

    def visit_While(self, node: ast.While):
        self.loop_stack.append(node)
        self.generic_visit(node)
        self.loop_stack.pop()

    def visit_Compare(self, node: ast.Compare):
        # 1. Quadratic Lookups: `if x in list_variable:` inside loops
        if self.loop_stack:
            for op in node.ops:
                if isinstance(op, (ast.In, ast.NotIn)):
                    right = node.comparators[0] if node.comparators else None
                    if isinstance(right, ast.Name):
                        fn_name = self.current_function.name if self.current_function else "module"
                        lineno = getattr(node, "lineno", 1)
                        snippet = self._get_line_snippet(lineno)
                        self.advice.append(
                            OptimizationAdvice(
                                file=self.file_path,
                                line=lineno,
                                rule_id="PERF-01-QUADRATIC-LOOKUP",
                                category="Algorithmic Complexity",
                                severity="high",
                                message=f"Linear lookup `in {right.id}` inside loop causes O(N^2) quadratic scaling. Convert `{right.id}` to a set outside the loop for O(1) lookups.",
                                original_snippet=snippet,
                                suggested_rewrite=f"{right.id}_set = set({right.id})\n# Inside loop: if ... in {right.id}_set:",
                                estimated_speedup="Up to 100x on large collections (O(N^2) -> O(N))",
                                function_name=fn_name,
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        full_call = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_call = func_name
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                full_call = f"{node.func.value.id}.{func_name}"

        lineno = getattr(node, "lineno", 1)
        snippet = self._get_line_snippet(lineno)
        fn_name = self.current_function.name if self.current_function else "module"

        # 2. Synchronous Blocking Calls inside Async Functions
        if isinstance(self.current_function, ast.AsyncFunctionDef):
            blocking_sync_calls = {
                "time.sleep": ("asyncio.sleep", "await asyncio.sleep(...)"),
                "requests.get": ("httpx.AsyncClient.get", "await client.get(...)"),
                "requests.post": ("httpx.AsyncClient.post", "await client.post(...)"),
                "requests.put": ("httpx.AsyncClient.put", "await client.put(...)"),
                "urllib.request.urlopen": ("httpx.AsyncClient.get", "await client.get(...)"),
            }
            is_blocking = full_call in blocking_sync_calls or (
                func_name == "urlopen"
            ) or (
                func_name == "sleep" and not full_call.startswith("asyncio.")
            )
            if is_blocking:
                replacement = blocking_sync_calls.get(full_call, ("async equivalent", "await async_call(...)"))
                self.advice.append(
                    OptimizationAdvice(
                        file=self.file_path,
                        line=lineno,
                        rule_id="PERF-02-SYNC-BLOCKING-IN-ASYNC",
                        category="Concurrency & Event Loop",
                        severity="high",
                        message=f"Synchronous blocking call `{full_call or func_name}` inside async def freezes the entire event loop.",
                        original_snippet=snippet,
                        suggested_rewrite=f"Use non-blocking `{replacement[0]}`: {replacement[1]}",
                        estimated_speedup="Prevents thread starvation and unblocks concurrent request handling",
                        function_name=fn_name,
                    )
                )

        # 3. Repeated Regex Compilation in Loops or Functions
        if self.loop_stack and full_call.startswith("re.") and func_name in ("search", "match", "findall", "finditer", "sub"):
            if node.args and isinstance(node.args[0], ast.Constant):
                self.advice.append(
                    OptimizationAdvice(
                        file=self.file_path,
                        line=lineno,
                        rule_id="PERF-03-REPEATED-REGEX-COMPILATION",
                        category="Regex Overhead",
                        severity="medium",
                        message=f"Calling `{full_call}` with a constant pattern inside a loop re-parses regex on every iteration. Pre-compile with `re.compile()` at module level.",
                        original_snippet=snippet,
                        suggested_rewrite="COMPILED_PATTERN = re.compile(...)\n# Inside loop: COMPILED_PATTERN.search(...)",
                        estimated_speedup="3x - 10x faster regex matching",
                        function_name=fn_name,
                    )
                )

        # 4. Repeated File I/O inside Loops
        if self.loop_stack and (func_name == "open" or full_call in ("Path.open", "Path.read_text", "Path.read_bytes")):
            self.advice.append(
                OptimizationAdvice(
                    file=self.file_path,
                    line=lineno,
                    rule_id="PERF-04-REPEATED-DISK-IO-IN-LOOP",
                    category="Disk I/O Bottleneck",
                    severity="high",
                    message="Opening file descriptors inside a loop causes excessive OS syscall overhead. Read or stream file outside loop.",
                    original_snippet=snippet,
                    suggested_rewrite="with open(...) as f:\n    data = f.read()\n# Iterate over data in memory",
                    estimated_speedup="10x - 50x reduction in disk syscalls",
                    function_name=fn_name,
                )
            )

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        # 5. Quadratic String Concatenation in Loops (`str_var += ...`)
        if self.loop_stack and isinstance(node.op, ast.Add):
            if isinstance(node.target, ast.Name):
                lineno = getattr(node, "lineno", 1)
                snippet = self._get_line_snippet(lineno)
                fn_name = self.current_function.name if self.current_function else "module"
                self.advice.append(
                    OptimizationAdvice(
                        file=self.file_path,
                        line=lineno,
                        rule_id="PERF-05-QUADRATIC-STRING-CONCAT",
                        category="Memory Allocation",
                        severity="medium",
                        message=f"In-place string accumulation `{node.target.id} += ...` inside loop creates intermediate string copies. Use a list and `''.join(list)`.",
                        original_snippet=snippet,
                        suggested_rewrite=f"chunks = []\n# Inside loop: chunks.append(...)\n{node.target.id} = ''.join(chunks)",
                        estimated_speedup="O(N^2) -> O(N) linear memory allocations",
                        function_name=fn_name,
                    )
                )
        self.generic_visit(node)


class PerformanceEngine:
    """Core analysis engine for AST performance analysis and optimization advice."""

    def analyze_source(self, file_path: str, source_code: str) -> List[OptimizationAdvice]:
        """Analyzes a single source string and returns optimization recommendations."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        lines = source_code.splitlines()
        visitor = ASTPerformanceVisitor(file_path=file_path, source_lines=lines)
        visitor.visit(tree)
        return visitor.advice

    def analyze_file(self, file_path: Path) -> List[OptimizationAdvice]:
        """Analyzes a file on disk."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.analyze_source(str(file_path), content)
        except Exception:
            return []

    def analyze_workspace(self, workspace_path: Path | str) -> List[OptimizationAdvice]:
        """Scans an entire workspace directory for performance anti-patterns."""
        root = Path(workspace_path)
        all_advice: List[OptimizationAdvice] = []
        if not root.is_dir():
            return all_advice

        for py_file in root.rglob("*.py"):
            if ".git" in py_file.parts or ".pytest_cache" in py_file.parts or "node_modules" in py_file.parts:
                continue
            all_advice.extend(self.analyze_file(py_file))

        return all_advice
