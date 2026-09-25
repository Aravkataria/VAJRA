"""
VAJRA GitHub Action Main Entrypoint
CLI and runner invoked during GitHub Actions workflows.
Lead Engineer: Arav Kataria
"""

import os
import sys
import json
from pathlib import Path
from vajra_bot.scanner import scan_content, scan_file, Finding
from vajra_bot.reviewer import GitHubReviewer, build_audit_summary_markdown


def run_action():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    fail_on_critical = os.environ.get("INPUT_FAIL_ON_CRITICAL", "false").lower() == "true"

    if not repo:
        print("❌ Error: GITHUB_REPOSITORY environment variable not set.")
        sys.exit(1)

    event_data = {}
    if event_path and Path(event_path).exists():
        try:
            event_data = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except Exception as e:
            print(f"⚠️ Could not parse event file {event_path}: {e}")

    # Determine Pull Request number & commit SHA
    pull_number = None
    commit_sha = None

    if "pull_request" in event_data:
        pull_number = event_data["pull_request"]["number"]
        commit_sha = event_data["pull_request"]["head"]["sha"]
    elif "issue" in event_data and "pull_request" in event_data["issue"]:
        pull_number = event_data["issue"]["number"]
        # Comment on a PR
        if "comment" in event_data:
            comment_body = event_data["comment"].get("body", "")
            if "@vajra" not in comment_body.lower():
                print("ℹ️ Comment does not mention @vajra. Skipping.")
                return

    if not pull_number:
        # Standalone scan on current directory
        print("🔍 Standalone scan mode: Scanning current repository files...")
        all_findings = []
        for p in Path(".").rglob("*"):
            if p.is_file() and not any(part.startswith(".") for part in p.parts):
                if p.suffix in (".py", ".js", ".ts", ".html", ".env", ".json"):
                    all_findings.extend(scan_file(p))

        print(f"✅ Standalone scan complete. Found {len(all_findings)} potential findings.")
        for f in all_findings:
            print(f"  [{f.severity}] {f.file}:{f.line} - {f.title} ({f.cwe})")
        return

    if not token:
        print("❌ Error: GITHUB_TOKEN is required to audit pull requests.")
        sys.exit(1)

    reviewer = GitHubReviewer(token=token, repo=repo, pull_number=pull_number, commit_sha=commit_sha)

    print(f"⚡ VAJRA Security Auditor initiated for PR #{pull_number} on {repo}...")
    reviewer.set_commit_status(state="pending", description="VAJRA AST security audit in progress...")

    # Fetch changed files from PR
    pr_files = reviewer.get_pr_files()
    print(f"📁 Fetched {len(pr_files)} changed files from PR #{pull_number}.")

    findings: list[Finding] = []
    inline_comments = []

    for file_info in pr_files:
        filename = file_info.get("filename", "")
        status = file_info.get("status", "")
        patch = file_info.get("patch", "")

        # Skip deleted files
        if status == "removed":
            continue

        # If file exists in checked-out workspace, scan full content; otherwise scan patch
        local_path = Path(filename)
        file_findings = []
        if local_path.is_file():
            file_findings = scan_file(local_path)
        elif patch:
            file_findings = scan_content(filename, patch)

        findings.extend(file_findings)

        # Build inline comment suggestions for high/critical findings
        for f in file_findings:
            if f.severity in ("CRITICAL", "HIGH"):
                comment_text = (
                    f"### ⚡ VAJRA Security Finding: {f.title} ({f.cwe})\n\n"
                    f"**Severity**: `{f.severity}`\n\n"
                    f"{f.description}\n"
                )
                if f.suggestion:
                    comment_text += f"\n```suggestion\n{f.suggestion}\n```\n"

                # Check if file has patch line references
                inline_comments.append({
                    "path": f.file,
                    "line": f.line,
                    "body": comment_text
                })

    # Build and post summary
    summary_md = build_audit_summary_markdown(findings, len(pr_files))

    criticals = [f for f in findings if f.severity == "CRITICAL"]
    highs = [f for f in findings if f.severity == "HIGH"]

    review_event = "COMMENT"
    if criticals:
        review_event = "REQUEST_CHANGES"
    elif not highs:
        review_event = "APPROVE"

    try:
        # Try to post formal PR review; fallback to PR comment if inline line ranges don't align with diff
        reviewer.post_pr_comment(summary_md)
        print("✅ Posted VAJRA Security Audit summary to PR thread.")
    except Exception as e:
        print(f"⚠️ Could not post PR comment: {e}")

    # Set final commit status
    if criticals:
        reviewer.set_commit_status(
            state="failure",
            description=f"VAJRA: {len(criticals)} critical vulnerabilities detected!"
        )
        if fail_on_critical:
            print("🚨 Critical vulnerabilities detected and fail-on-critical is enabled.")
            sys.exit(1)
    else:
        reviewer.set_commit_status(
            state="success",
            description="VAJRA: Security audit passed clean."
        )

    print("🎉 VAJRA Security Audit completed successfully.")


if __name__ == "__main__":
    run_action()
