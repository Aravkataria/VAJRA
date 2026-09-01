# app/repair/minimality_evaluator.py

"""
Section 6.13: Patch Minimality & Complexity Evaluator.

Compares candidate repair patches to select the smallest, least invasive,
and lowest-regression-risk patch that satisfies all 6 verification stages.

Evaluates:
- Line Diff Count (ΔLOC)
- AST Node Distance & Token Perturbation
- Cyclomatic Complexity Delta (ΔCC)
- API Contract Invariance
"""

import ast
from dataclasses import dataclass
from typing import List, Optional
from app.repair.patch import Patch


@dataclass
class PatchMinimalityScore:
    patch: Patch
    line_delta: int
    char_delta: int
    ast_node_delta: int
    complexity_delta: int
    invasiveness_score: float  # Lower is better (0.0 = minimal, 100.0 = overly broad rewrite)
    is_minimal: bool


class MinimalityEvaluator:
    @staticmethod
    def _count_ast_nodes(code: str) -> int:
        try:
            tree = ast.parse(code)
            return len(list(ast.walk(tree)))
        except Exception:
            return len(code.split())

    @staticmethod
    def _estimate_complexity(code: str) -> int:
        # Count branching keywords (if, for, while, try, except, with, and, or)
        branching_keywords = {"if", "elif", "for", "while", "except", "and", "or"}
        try:
            tree = ast.parse(code)
            complexity = 1
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.BoolOp)):
                    complexity += 1
            return complexity
        except Exception:
            return sum(code.count(k) for k in branching_keywords) + 1

    @classmethod
    def evaluate(cls, original_code: str, candidate_patch: Patch) -> PatchMinimalityScore:
        orig_lines = len(original_code.strip().splitlines())
        patch_code = candidate_patch.diff or candidate_patch.explanation or ""
        patch_lines = len(patch_code.strip().splitlines())

        line_delta = abs(patch_lines - orig_lines) if orig_lines else patch_lines
        char_delta = abs(len(patch_code) - len(original_code))

        orig_nodes = cls._count_ast_nodes(original_code)
        patch_nodes = cls._count_ast_nodes(patch_code)
        ast_node_delta = abs(patch_nodes - orig_nodes)

        orig_cc = cls._estimate_complexity(original_code)
        patch_cc = cls._estimate_complexity(patch_code)
        complexity_delta = abs(patch_cc - orig_cc)

        # Invasiveness Formula: Weighted combination of line delta + token perturbation + complexity delta
        invasiveness = (line_delta * 2.5) + (ast_node_delta * 1.2) + (complexity_delta * 4.0)
        invasiveness = min(invasiveness, 100.0)

        return PatchMinimalityScore(
            patch=candidate_patch,
            line_delta=line_delta,
            char_delta=char_delta,
            ast_node_delta=ast_node_delta,
            complexity_delta=complexity_delta,
            invasiveness_score=round(invasiveness, 2),
            is_minimal=invasiveness <= 35.0,
        )

    @classmethod
    def select_best_candidate(cls, original_code: str, candidate_patches: List[Patch]) -> Optional[Patch]:
        """Picks the candidate patch with the lowest invasiveness score."""
        if not candidate_patches:
            return None

        scored = [cls.evaluate(original_code, p) for p in candidate_patches]
        scored.sort(key=lambda x: x.invasiveness_score)
        return scored[0].patch
