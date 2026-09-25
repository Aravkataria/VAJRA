"""
VAJRA GitHub PR Reviewer & Bot Integration
Interfaces with GitHub REST API to post inline security reviews and audit reports.
Lead Engineer: Arav Kataria
"""

import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from vajra_bot.scanner import Finding


class GitHubReviewer:
    def __init__(self, token: str, repo: str, pull_number: int, commit_sha: Optional[str] = None):
        self.token = token
        self.repo = repo
        self.pull_number = pull_number
        self.commit_sha = commit_sha
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "VAJRA-Security-Bot"
        }

    def _request(self, method: str, path: str, data: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.api_base}{path}"
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=payload, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if resp.status == 204:
                    return None
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            print(f"⚠️ GitHub API Error [{e.code}] on {method} {path}: {err_body}")
            raise

    def get_pr_files(self) -> List[Dict[str, Any]]:
        """Retrieves the list of changed files and patches for the pull request."""
        path = f"/repos/{self.repo}/pulls/{self.pull_number}/files?per_page=100"
        return self._request("GET", path) or []

    def post_pr_comment(self, body: str) -> Optional[Dict[str, Any]]:
        """Posts a general comment on the Pull Request thread."""
        path = f"/repos/{self.repo}/issues/{self.pull_number}/comments"
        return self._request("POST", path, {"body": body})

    def post_inline_review(self, event: str, summary: str, comments: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Posts a formal Pull Request Review with inline line-by-line comments.
        event: 'APPROVE', 'REQUEST_CHANGES', or 'COMMENT'
        """
        path = f"/repos/{self.repo}/pulls/{self.pull_number}/reviews"
        payload = {
            "body": summary,
            "event": event,
            "comments": comments
        }
        if self.commit_sha:
            payload["commit_id"] = self.commit_sha
        return self._request("POST", path, payload)

    def set_commit_status(self, state: str, description: str, target_url: Optional[str] = None):
        """
        Sets the commit status check (e.g. 'VAJRA Security Audit').
        state: 'pending', 'success', 'failure', 'error'
        """
        if not self.commit_sha:
            return
        path = f"/repos/{self.repo}/statuses/{self.commit_sha}"
        payload = {
            "state": state,
            "description": description[:140],
            "context": "VAJRA",
            "target_url": target_url or f"https://github.com/{self.repo}/pull/{self.pull_number}"
        }
        try:
            self._request("POST", path, payload)
        except Exception as e:
            print(f"⚠️ Could not set commit status: {e}")


def build_audit_summary_markdown(findings: List[Finding], files_scanned_count: int) -> str:
    """Builds a formatted forensic security audit card for the PR comment."""
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    highs = [f for f in findings if f.severity == "HIGH"]
    mediums = [f for f in findings if f.severity == "MEDIUM"]

    passed = len(criticals) == 0 and len(highs) == 0
    status_badge = "🛡️ **ALL CHECKS PASSED**" if passed else "⚠️ **SECURITY ACTION REQUIRED**"
    status_desc = "No critical AST sinks or secret exposures detected." if passed else f"Found **{len(criticals)} critical** and **{len(highs)} high** severity issues."

    lines = [
        "## ⚡ VAJRA Security Auditor",
        "> **Autonomous AST & Cryptographic Vulnerability Review**  ",
        "> *Engineered by [Arav Kataria](https://github.com/Aravkataria) • Zero-Retention Security Architecture*",
        "",
        "---",
        "",
        f"### {status_badge}",
        f"{status_desc}",
        "",
        "| Metric | Result |",
        "| :--- | :--- |",
        f"| **Files Scanned** | `{files_scanned_count}` changed files |",
        f"| **Critical Vulnerabilities** | `{len(criticals)}` |",
        f"| **High Severity Issues** | `{len(highs)}` |",
        f"| **Medium / Warning** | `{len(mediums)}` |",
        f"| **VAJRA Safety Score** | `{max(0, 100 - len(criticals)*35 - len(highs)*15 - len(mediums)*5)}/100` |",
        ""
    ]

    if findings:
        lines.append("### 🔍 Detected Vulnerability Findings")
        for idx, f in enumerate(findings, start=1):
            severity_icon = "🚨" if f.severity == "CRITICAL" else ("⚠️" if f.severity == "HIGH" else "ℹ️")
            lines.append(f"#### {idx}. {severity_icon} [{f.severity}] {f.title} ({f.cwe})")
            lines.append(f"- **Location**: `{f.file}` (Line {f.line})")
            lines.append(f"- **Vulnerability Details**: {f.description}")
            if f.suggestion:
                lines.append(f"- **Remediation Suggestion**:\n```python\n{f.suggestion}\n```")
            lines.append("")

    lines.append("---")
    lines.append("*💡 To re-run this scan, comment `@vajra review` or push new commits to this branch.*")
    return "\n".join(lines)
