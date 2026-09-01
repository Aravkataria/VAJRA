# app/report/html_renderer.py

"""
Renders an AssuranceReport as a single self-contained HTML page for VAJRA.
"""

import html
from typing import Optional

from app.report.models import AssuranceReport, AttemptReport

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 980px;
       margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; background: #fafafa; }
h1 { margin-bottom: 0.2rem; }
.subtitle { color: #666; margin-top: 0; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.5rem 0; }
.summary .stat { background: #fff; border: 1px solid #ddd; border-radius: 8px;
                  padding: 0.75rem 1rem; min-width: 120px; }
.summary .stat .n { font-size: 1.6rem; font-weight: 700; display: block; }
.summary .stat .l { font-size: 0.8rem; color: #666; }
.banner { background: #fff8e6; border: 1px solid #f0d375; border-radius: 8px;
          padding: 0.75rem 1rem; margin: 1rem 0; font-size: 0.9rem; }
.position { font-size: 0.85rem; color: #555; border-left: 3px solid #ccc;
            padding-left: 0.75rem; margin: 1.5rem 0; }
.attempt { background: #fff; border: 1px solid #ddd; border-radius: 8px;
           padding: 1rem 1.25rem; margin: 1rem 0; }
.attempt-header { display: flex; justify-content: space-between; align-items: baseline;
                   flex-wrap: wrap; gap: 0.5rem; }
.badge { display: inline-block; border-radius: 999px; padding: 0.15rem 0.7rem;
         font-size: 0.78rem; font-weight: 600; }
.badge.verified { background: #dff5e1; color: #196e2c; }
.badge.non-repair { background: #fdeaea; color: #9c1c1c; }
.badge.status-resolved { background: #dff5e1; color: #196e2c; }
.badge.status-remaining { background: #fdeaea; color: #9c1c1c; }
.badge.status-unknown { background: #eee; color: #555; }
.loc { color: #666; font-size: 0.85rem; font-family: ui-monospace, monospace; }
.reason { margin: 0.5rem 0; }
details { margin: 0.5rem 0; }
summary { cursor: pointer; font-weight: 600; font-size: 0.88rem; }
pre { background: #0d1117; color: #c9d1d9; padding: 0.75rem; border-radius: 6px;
      overflow-x: auto; font-size: 0.8rem; }
table.stages { width: 100%; border-collapse: collapse; margin-top: 0.4rem; font-size: 0.85rem; }
table.stages th, table.stages td { text-align: left; padding: 0.3rem 0.5rem;
                                     border-bottom: 1px solid #eee; }
.pass { color: #196e2c; font-weight: 600; }
.fail { color: #9c1c1c; font-weight: 600; }
.limitations { font-size: 0.8rem; color: #7a5b00; margin-top: 0.5rem; }
"""


def _esc(value: Optional[str]) -> str:
    return html.escape(value if value is not None else "", quote=True)


def _stage_rows(stages) -> str:
    rows = []
    for stage in stages:
        verdict = '<span class="pass">PASS</span>' if stage["verified"] else '<span class="fail">FAIL</span>'
        rows.append(
            f"<tr><td>{_esc(stage['method'])}</td><td>{verdict}</td>"
            f"<td>{_esc(stage['reason'])}</td></tr>"
        )
    return "".join(rows)


def _model_attempt_rows(attempts) -> str:
    rows = []
    for a in attempts:
        rows.append(
            f"<tr><td>{_esc(a['model'])}</td><td>{_esc(a['status'])}</td>"
            f"<td>{_esc(a['reason'])}</td></tr>"
        )
    return "".join(rows)


def _render_attempt(report: AttemptReport) -> str:
    outcome_class = "verified" if report.outcome == "verified_repair" else "non-repair"
    outcome_label = "Verified repair" if report.outcome == "verified_repair" else "Structured non-repair"

    status = report.finding_status or "unknown"
    status_badge = f'<span class="badge status-{_esc(status)}">{_esc(status)}</span>'

    diff_block = ""
    if report.patch_diff:
        diff_block = (
            "<details><summary>Patch diff</summary>"
            f"<pre>{_esc(report.patch_diff)}</pre></details>"
        )

    assessment_block = ""
    if report.assessment:
        a = report.assessment
        assessment_block = (
            "<details><summary>Security Analyst assessment</summary>"
            "<ul>"
            f"<li><b>Confirmed:</b> {_esc(str(a.get('confirmed')))}</li>"
            f"<li><b>Confidence:</b> {_esc(str(a.get('confidence')))}</li>"
            f"<li><b>Root cause:</b> {_esc(a.get('root_cause'))}</li>"
            f"<li><b>Impact:</b> {_esc(a.get('impact'))}</li>"
            f"<li><b>Recommended action:</b> {_esc(a.get('recommended_action'))}</li>"
            "</ul></details>"
        )

    model_attempts_block = ""
    if report.model_attempts:
        model_attempts_block = (
            "<details><summary>Repair model attempts "
            f"({_esc(str(len(report.model_attempts)))}, retries: "
            f"{_esc(str(report.repair_retry_count))})</summary>"
            '<table class="stages"><tr><th>Model</th><th>Status</th><th>Reason</th></tr>'
            f"{_model_attempt_rows(report.model_attempts)}</table></details>"
        )

    stages_block = ""
    if report.verification_stages:
        stages_block = (
            "<details open><summary>Verification stages</summary>"
            '<table class="stages"><tr><th>Stage</th><th>Result</th><th>Reason</th></tr>'
            f"{_stage_rows(report.verification_stages)}</table></details>"
        )

    limitations_block = ""
    if report.limitations:
        items = "".join(f"<li>{_esc(item)}</li>" for item in report.limitations)
        limitations_block = f'<div class="limitations"><b>Limitations:</b><ul>{items}</ul></div>'

    return f"""
<div class="attempt">
  <div class="attempt-header">
    <div>
      <span class="badge {outcome_class}">{_esc(outcome_label)}</span>
      {status_badge}
      <div class="loc">{_esc(report.file)}:{_esc(str(report.line))} &middot; {_esc(report.function)}
        &middot; {_esc(report.vulnerability_type)} ({_esc(report.severity)})</div>
    </div>
    <div class="loc">{_esc(report.decision_route)}</div>
  </div>
  <p class="reason">{_esc(report.outcome_reason)}</p>
  {assessment_block}
  {model_attempts_block}
  {diff_block}
  {stages_block}
  {limitations_block}
</div>
"""


def render_assurance_report_html(report: AssuranceReport) -> str:
    summary = report.summary
    stats = [
        (summary.get("initial_findings", 0), "Initial findings"),
        (summary.get("verified_repairs", 0), "Verified repairs"),
        (summary.get("structured_non_repairs", 0), "Structured non-repairs"),
        (summary.get("final_findings", 0), "Findings remaining"),
    ]
    stat_html = "".join(
        f'<div class="stat"><span class="n">{_esc(str(n))}</span><span class="l">{_esc(label)}</span></div>'
        for n, label in stats
    )

    unperformed = "".join(f"<li>{_esc(item)}</li>" for item in report.unperformed_checks)
    banner = (
        '<div class="banner"><b>Not yet performed for this scan</b> '
        "(Future work, not silently assumed to have passed): "
        f"<ul>{unperformed}</ul></div>"
    )

    attempts_html = "".join(_render_attempt(a) for a in report.attempts) or (
        "<p>No findings required a repair attempt.</p>"
    )

    tool_versions = ", ".join(f"{_esc(k)}={_esc(v)}" for k, v in report.tool_versions.items())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VAJRA Repair Assurance Report -- {_esc(report.workspace_id)}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>Repair Assurance Report</h1>
<p class="subtitle">Workspace {_esc(report.workspace_id)} &middot; generated {_esc(report.generated_at)} &middot; {tool_versions}</p>

<div class="summary">{stat_html}</div>

{banner}

<h2>Attempts</h2>
{attempts_html}

<p class="position">{_esc(report.to_dict()['position'])}</p>
</body>
</html>
"""


def render_attempt_report_html(attempt: AttemptReport, workspace_id: Optional[str] = None) -> str:
    ws_text = f" &middot; Workspace {_esc(workspace_id)}" if workspace_id else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VAJRA Attempt Assurance -- {_esc(attempt.attempt_id)}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>Repair Attempt Assurance Record</h1>
<p class="subtitle">Attempt ID {_esc(attempt.attempt_id)}{ws_text} &middot; {_esc(attempt.generated_at)}</p>

{_render_attempt(attempt)}

<p><a href="/dashboard">&larr; Back to Dashboard</a></p>
</body>
</html>
"""