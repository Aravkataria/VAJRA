# app/analysis/workspace_scan.py

from pathlib import Path
from typing import Any, Dict, List

from app.analysis.python_static import analyze_file
from app.analysis.performance_engine import PerformanceEngine, OptimizationAdvice


def scan_workspace(workspace_path):
    """
    Walk a workspace and run the static analyzer over every
    Python file found. Returns a list of Finding objects with
    paths relative to the workspace root.
    """

    workspace_path = Path(workspace_path)

    if not workspace_path.is_dir():
        raise FileNotFoundError(f"Workspace not found: {workspace_path}")

    all_findings = []

    for file in sorted(workspace_path.rglob("*.py")):
        if not file.is_file():
            continue

        relative_path = str(file.relative_to(workspace_path))

        findings = analyze_file(str(file))

        for finding in findings:
            finding.file = relative_path

        all_findings.extend(findings)

    return all_findings


def scan_workspace_performance(workspace_path: Path | str) -> List[OptimizationAdvice]:
    """
    Scans the workspace for AST complexity hotspots and code optimization opportunities.
    """
    workspace_path = Path(workspace_path)
    if not workspace_path.is_dir():
        raise FileNotFoundError(f"Workspace not found: {workspace_path}")

    engine = PerformanceEngine()
    advice_list = engine.analyze_workspace(workspace_path)

    for advice in advice_list:
        try:
            rel = Path(advice.file).relative_to(workspace_path)
            advice.file = str(rel)
        except Exception:
            pass

    return advice_list


def scan_workspace_full(workspace_path: Path | str) -> Dict[str, Any]:
    """
    Executes a dual security + performance optimization scan over the workspace.
    """
    security_findings = scan_workspace(workspace_path)
    performance_advice = scan_workspace_performance(workspace_path)

    return {
        "security_findings": security_findings,
        "performance_advice": performance_advice,
        "security_summary": summarize_findings(security_findings),
        "performance_summary": {
            "total_optimizations": len(performance_advice),
            "by_severity": {
                "high": len([a for a in performance_advice if a.severity == "high"]),
                "medium": len([a for a in performance_advice if a.severity == "medium"]),
                "low": len([a for a in performance_advice if a.severity == "low"]),
            },
        },
    }


def summarize_findings(findings):
    """
    Roll a list of Finding objects up into counts by severity
    and by vulnerability type.
    """

    by_severity = {}
    by_type = {}

    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_type[finding.vulnerability_type] = by_type.get(finding.vulnerability_type, 0) + 1

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_type": by_type,
    }