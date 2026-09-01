# app/dashboard/renderer.py

"""
Renders the Dashboard for VAJRA.
"""

import html
from typing import Any, Dict, List, Optional

_STYLE = """
:root {
  --bg: #f8fafc;
  --surface: #ffffff;
  --border: #e2e8f0;
  --text: #0f172a;
  --muted: #64748b;
  --primary: #2563eb;
  --primary-hover: #1d4ed8;
  --success: #16a34a;
  --success-bg: #f0fdf4;
  --danger: #dc2626;
  --danger-bg: #fef2f2;
  --warning: #d97706;
  --warning-bg: #fffbeb;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background-color: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 2rem 1.5rem;
}

.container {
  max-width: 1120px;
  margin: 0 auto;
}

header {
  margin-bottom: 2rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 1.5rem;
}

.logo-row {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
}

h1 {
  margin: 0;
  font-size: 1.875rem;
  font-weight: 800;
  letter-spacing: -0.025em;
  color: #0f172a;
}

.badge-tag {
  background: #e0e7ff;
  color: #3730a3;
  padding: 0.2rem 0.6rem;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.subtitle {
  color: var(--muted);
  margin: 0.4rem 0 0 0;
  font-size: 0.95rem;
}

.github-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0,0,0,0.03);
  margin-bottom: 2rem;
}

.github-input-group {
  display: flex;
  gap: 0.75rem;
  margin-top: 0.75rem;
  flex-wrap: wrap;
}

.github-input {
  flex: 1;
  min-width: 280px;
  padding: 0.65rem 1rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  font-size: 0.9rem;
  font-family: inherit;
}

.github-input:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 2.5rem;
}

.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.25rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.03);
}

.stat-val {
  font-size: 2rem;
  font-weight: 800;
  line-height: 1;
  margin-bottom: 0.35rem;
}

.stat-label {
  font-size: 0.85rem;
  color: var(--muted);
  font-weight: 500;
}

.stat-card.verified .stat-val { color: var(--success); }
.stat-card.declined .stat-val { color: var(--danger); }
.stat-card.total .stat-val { color: var(--primary); }

.section-title {
  font-size: 1.25rem;
  font-weight: 700;
  margin: 2rem 0 1rem 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.03);
  overflow: hidden;
  margin-bottom: 2rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}

th {
  background: #f1f5f9;
  text-align: left;
  padding: 0.75rem 1rem;
  font-weight: 600;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
}

td {
  padding: 0.875rem 1rem;
  border-bottom: 1px solid var(--border);
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8fafc; }

.badge {
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}

.badge-success { background: var(--success-bg); color: var(--success); }
.badge-danger { background: var(--danger-bg); color: var(--danger); }
.badge-warning { background: var(--warning-bg); color: var(--warning); }
.badge-neutral { background: #f1f5f9; color: var(--muted); }

.declined-card {
  background: var(--surface);
  border: 1px solid #fecaca;
  border-left: 4px solid var(--danger);
  border-radius: 8px;
  padding: 1.25rem;
  margin-bottom: 1rem;
}

.declined-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.loc {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.85rem;
  color: var(--muted);
}

.stage-tag {
  background: #fee2e2;
  color: #991b1b;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-weight: 600;
  font-size: 0.8rem;
}

.declined-reason {
  margin: 0.5rem 0;
  font-size: 0.92rem;
  color: #334155;
}

pre {
  background: #0f172a;
  color: #e2e8f0;
  padding: 0.75rem 1rem;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 0.8rem;
  margin: 0.5rem 0;
}

details summary {
  cursor: pointer;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--primary);
  margin-top: 0.5rem;
}

a.btn, button.btn {
  display: inline-block;
  background: var(--primary);
  color: white;
  text-decoration: none;
  padding: 0.45rem 0.85rem;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 500;
  border: none;
  cursor: pointer;
}

a.btn:hover, button.btn:hover { background: var(--primary-hover); }
a.link { color: var(--primary); text-decoration: none; font-weight: 500; }
a.link:hover { text-decoration: underline; }

.empty-state {
  padding: 2.5rem;
  text-align: center;
  color: var(--muted);
}
"""


def _esc(val: Any) -> str:
    return html.escape(str(val) if val is not None else "", quote=True)


def render_dashboard_html(
    reports: List[Dict[str, Any]],
    declined_attempts: List[Dict[str, Any]],
) -> str:
    total_scans = len(reports)
    total_initial = sum(r.get("summary", {}).get("initial_findings", 0) for r in reports)
    total_verified = sum(r.get("summary", {}).get("verified_repairs", 0) for r in reports)
    total_declined = sum(r.get("summary", {}).get("structured_non_repairs", 0) for r in reports)

    if reports:
        report_rows = []
        for r in reports:
            ws_id = r.get("workspace_id", "unknown")
            gen_at = r.get("generated_at", "")
            summary = r.get("summary", {})
            init_f = summary.get("initial_findings", 0)
            final_f = summary.get("final_findings", 0)
            verified = summary.get("verified_repairs", 0)
            declined = summary.get("structured_non_repairs", 0)

            status_badge = (
                '<span class="badge badge-success">Clean / Repaired</span>'
                if final_f == 0
                else '<span class="badge badge-warning">Remaining Findings</span>'
            )

            report_rows.append(
                f"""
                <tr>
                  <td><b>{_esc(ws_id)}</b></td>
                  <td>{status_badge}</td>
                  <td>{init_f} &rarr; <b>{final_f}</b></td>
                  <td><span class="badge badge-success">{verified} verified</span></td>
                  <td><span class="badge badge-danger">{declined} non-repair</span></td>
                  <td><span class="loc">{_esc(gen_at)}</span></td>
                  <td>
                    <a class="btn" href="/workspace/{_esc(ws_id)}/report.html" target="_blank">HTML</a>
                    <a class="btn" style="background:#475569;" href="/workspace/{_esc(ws_id)}/report.json" target="_blank">JSON</a>
                  </td>
                </tr>
                """
            )
        reports_table = f"""
        <table>
          <thead>
            <tr>
              <th>Workspace</th>
              <th>Status</th>
              <th>Findings (Before &rarr; After)</th>
              <th>Verified Repairs</th>
              <th>Declined / Unrepaired</th>
              <th>Timestamp</th>
              <th>Assurance Report</th>
            </tr>
          </thead>
          <tbody>
            {"".join(report_rows)}
          </tbody>
        </table>
        """
    else:
        reports_table = '<div class="empty-state">No repository scans recorded yet. Enter a GitHub URL above to start an evidence-driven repair scan.</div>'

    if declined_attempts:
        declined_cards = []
        for att in declined_attempts[:8]:
            att_id = att.get("attempt_id", "")
            finding = att.get("finding", {})
            loc = f"{finding.get('file', '')}:{finding.get('line', '')} ({finding.get('vulnerability_type', '')})"
            reason = att.get("outcome_reason", "")
            verification = att.get("verification", {})
            final_stage = verification.get("final_method") or "decision-engine"
            diff = att.get("patch", {}).get("diff") if att.get("patch") else None

            diff_html = ""
            if diff:
                diff_html = f"<details><summary>View Rejected Patch Diff</summary><pre>{_esc(diff)}</pre></details>"

            declined_cards.append(
                f"""
                <div class="declined-card">
                  <div class="declined-header">
                    <div>
                      <span class="stage-tag">{_esc(final_stage)}</span>
                      <span class="loc" style="margin-left: 0.5rem;">{_esc(loc)}</span>
                    </div>
                    <div>
                      <a class="link" href="/attempts/{_esc(att_id)}" target="_blank" style="font-size:0.8rem;">View Assurance Record &rarr;</a>
                    </div>
                  </div>
                  <div class="declined-reason"><b>Why declined:</b> {_esc(reason)}</div>
                  {diff_html}
                </div>
                """
            )
        declined_html = "".join(declined_cards)
    else:
        declined_html = '<div class="empty-state">No declined attempts recorded yet.</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VAJRA &middot; Assurance Dashboard</title>
  <style>{_STYLE}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-row">
        <h1>VAJRA</h1>
        <span class="badge-tag">Cyber-Reasoning & Software Repair</span>
      </div>
      <p class="subtitle">Evidence-driven repair lifecycle &middot; Independent multi-stage verification &middot; Transparent assurance</p>
    </header>

    <!-- GitHub Direct Ingestion Box -->
    <div class="github-card">
      <div style="font-weight: 700; font-size: 1.05rem;">🔗 Scan GitHub Repository Directly</div>
      <p style="color: var(--muted); font-size: 0.85rem; margin: 0.25rem 0 0 0;">
        Enter any public repository link or branch to clone, extract AST evidence, generate repairs, and run independent verification.
      </p>
      <form id="ghForm" onsubmit="handleGithubScan(event)" class="github-input-group">
        <input type="url" id="ghUrl" class="github-input" placeholder="https://github.com/owner/repository (e.g. https://github.com/Aravkataria/VAJRA-test)" required>
        <button type="submit" id="ghBtn" class="btn" style="padding: 0.65rem 1.25rem; font-weight: 600;">
          <span>Scan & Repair</span>
        </button>
      </form>
      <div id="ghStatus" style="font-size: 0.85rem; margin-top: 0.5rem; display: none;"></div>
    </div>

    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-val">{total_scans}</div>
        <div class="stat-label">Total Workspaces Scanned</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{total_initial}</div>
        <div class="stat-label">Vulnerabilities Detected</div>
      </div>
      <div class="stat-card verified">
        <div class="stat-val">{total_verified}</div>
        <div class="stat-label">Verified & Applied Repairs</div>
      </div>
      <div class="stat-card declined">
        <div class="stat-val">{total_declined}</div>
        <div class="stat-label">Unsafe / Non-Repairs Declined</div>
      </div>
    </div>

    <div class="section-title">
      <span>🛡️</span>
      <span>Why We Decline: The Evidence-Based Difference</span>
    </div>
    <p style="color: var(--muted); font-size: 0.9rem; margin-top: -0.5rem; margin-bottom: 1rem;">
      VAJRA never assumes generated patches are safe. Every candidate must pass independent syntax checks, static re-scanning, dynamic exploit PoCs, functional regression test suites, dynamic fuzzing, and mutation testing.
    </p>
    <div class="declined-container">
      {declined_html}
    </div>

    <div class="section-title">
      <span>📋</span>
      <span>Recent Workspace Assurance Reports</span>
    </div>
    <div class="card">
      {reports_table}
    </div>
  </div>

  <script>
    async function handleGithubScan(e) {{
      e.preventDefault();
      const url = document.getElementById('ghUrl').value.trim();
      const btn = document.getElementById('ghBtn');
      const status = document.getElementById('ghStatus');
      if (!url) return;

      btn.disabled = true;
      btn.innerHTML = '<span>Cloning & Scanning...</span>';
      status.style.display = 'block';
      status.style.color = '#2563eb';
      status.textContent = 'Cloning GitHub repository, extracting AST evidence, and running verification pipeline...';

      try {{
        const resp = await fetch('/scan-github', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ url: url }})
        }});
        if (!resp.ok) {{
          const err = await resp.json();
          throw new Error(err.detail || 'Scan failed');
        }}
        const data = await resp.json();
        status.style.color = '#16a34a';
        status.textContent = 'Scan completed! Reloading dashboard...';
        setTimeout(() => window.location.reload(), 1000);
      }} catch (err) {{
        status.style.color = '#dc2626';
        status.textContent = 'Error: ' + err.message;
        btn.disabled = false;
        btn.innerHTML = '<span>Scan & Repair</span>';
      }}
    }}
  </script>
</body>
</html>
"""