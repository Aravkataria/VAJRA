# app/analysis/adapters/native_ast_adapter.py

from typing import List
from app.analysis.adapters.base import BaseAnalysisAdapter
from app.analysis.finding import Finding
from app.analysis.workspace_scan import scan_workspace


class NativeASTAdapter(BaseAnalysisAdapter):
    @property
    def name(self) -> str:
        return "Native Python AST Analyzer"

    def analyze(self, workspace_path: str) -> List[Finding]:
        return scan_workspace(workspace_path)
