# app/verification/mutation_verifier.py

"""
Patch Mutation Testing for VAJRA.
"""

import ast
from pathlib import Path
from typing import List, Optional

from app.repair.patch import Patch
from app.verification.result import VerificationResult
from app.verification.security_test.poc_templates import SUPPORTED_DYNAMIC_TYPES
from app.verification.security_test.runner import run_poc
from app.verification.verification_model import VerificationModel


def _enclosing_function(source: str, line: int) -> str:
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", node.lineno)
                if start <= line <= end:
                    return node.name
    except Exception:
        pass
    return "module"


class _AstMutator(ast.NodeTransformer):
    def __init__(self, target_line: int):
        self.target_line = target_line
        self.mutated = False

    def visit_Compare(self, node: ast.Compare):
        if getattr(node, "lineno", None) == self.target_line and not self.mutated:
            self.mutated = True
            new_ops = []
            for op in node.ops:
                if isinstance(op, ast.Eq):
                    new_ops.append(ast.NotEq())
                elif isinstance(op, ast.NotEq):
                    new_ops.append(ast.Eq())
                elif isinstance(op, ast.In):
                    new_ops.append(ast.NotIn())
                elif isinstance(op, ast.NotIn):
                    new_ops.append(ast.In())
                else:
                    new_ops.append(op)
            node.ops = new_ops
        return self.generic_visit(node)


class PatchMutationVerifier(VerificationModel):
    def __init__(self, max_mutants: int = 3):
        self.max_mutants = max_mutants

    def _generate_mutants(self, patched_source: str, target_line: int) -> List[str]:
        mutants = []
        try:
            tree = ast.parse(patched_source)
            transformer = _AstMutator(target_line)
            mutated_tree = transformer.visit(tree)
            if transformer.mutated:
                mutants.append(ast.unparse(mutated_tree))
        except Exception:
            pass

        reverts = [
            ("yaml.safe_load", "yaml.load"),
            ("literal_eval", "eval"),
            ("shell=False", "shell=True"),
        ]
        for safe, dangerous in reverts:
            if safe in patched_source:
                mutants.append(patched_source.replace(safe, dangerous, 1))

        return mutants[: self.max_mutants]

    def verify(self, patch: Patch, workspace_path: Path) -> VerificationResult:
        vuln_type = patch.vulnerability_type
        if vuln_type not in SUPPORTED_DYNAMIC_TYPES:
            return VerificationResult(
                patch,
                True,
                "patch-mutation-testing:skipped",
                f"Finding type {vuln_type!r} has no dynamic test to mutate; skipped.",
            )

        root = Path(workspace_path).resolve()
        source_path = (root / patch.file).resolve()
        try:
            original_source = source_path.read_text(encoding="utf-8")
            patched_source = patch.apply_to_source(original_source)
        except Exception as exc:
            return VerificationResult(
                patch, False, "patch-mutation-testing", f"Could not construct source: {exc}"
            )

        mutants = self._generate_mutants(patched_source, patch.line)
        if not mutants:
            return VerificationResult(
                patch,
                True,
                "patch-mutation-testing:skipped",
                "No candidate AST mutations generated for target line; skipped.",
            )

        caught_count = 0
        call_name = getattr(patch, "call_name", None)

        for mutant_source in mutants:
            target_fn = _enclosing_function(mutant_source, patch.line)
            run = run_poc(
                workspace_path=workspace_path,
                relative_file=patch.file,
                source=mutant_source,
                function_name=target_fn,
                vulnerability_type=vuln_type,
                call_name=call_name,
                timeout=5,
            )
            if run.exploited or run.error:
                caught_count += 1

        total = len(mutants)
        return VerificationResult(
            patch,
            True,
            "patch-mutation-testing",
            f"Security verification caught {caught_count}/{total} synthetic mutations of the fix.",
        )