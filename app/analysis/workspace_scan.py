# app/analysis/workspace_scan.py

from pathlib import Path

from app.analysis.python_static import analyze_file


def scan_workspace(workspace_path):
    """
    Walk a workspace and run the static analyzer over every
    Python file found. Returns a list of Finding objects with
    paths relative to the workspace root.

    Only .py files are analyzed for now — other languages will
    get their own analyzers later.
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

        # Report paths relative to the workspace, not the
        # absolute disk path, so results are portable.
        for finding in findings:
            finding.file = relative_path

        all_findings.extend(findings)

    return all_findings


def summarize_findings(findings):
    """
    Roll a list of Finding objects up into counts by severity
    and by vulnerability type, for a quick-glance overview.
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