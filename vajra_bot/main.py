"""
VAJRA GitHub Action Main Entrypoint
Full Multi-Stage Architecture:
  Stage 1: AST & Secret Signatures (Fast Rule Filter)
  Stage 2: Semantic & Neural Finder (Contextual Sinks)
  Stage 3: VAJRA LLM Remediation (Patch Generation)
  Stage 4: AST Self-Verification (Syntax & Secondary Sink Validation)
Lead Engineer: Arav Kataria
"""

import os
import sys
import json
from pathlib import Path
from vajra_bot.scanner import scan_content, scan_file, Finding
from vajra_bot.finder import SemanticFinder
from vajra_bot.remediator import ModelRemediator
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
        if "comment" in event_data:
            comment_body = event_data["comment"].get("body", "")
            if "@vajra" not in comment_body.lower():
                print("ℹ️ Comment does not mention @vajra. Skipping.")
                return

    remediator = ModelRemediator()

    if not pull_number:
        # Standalone scan on current directory
        print("🔍 Standalone scan mode: Scanning current repository files...")
        all_findings = []
        for p in Path(".").rglob("*"):
            if p.is_file() and not any(part.startswith(".") for part in p.parts):
                if p.suffix in (".py", ".js", ".ts", ".html", ".env", ".json"):
                    # Stage 1: AST & Secret scan
                    findings = scan_file(p)
                    # Stage 2: Semantic Finder scan
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        findings.extend(SemanticFinder.scan_context(str(p), content))
                    except Exception:
                        pass
                    all_findings.extend(findings)

        print(f"✅ Standalone scan complete. Found {len(all_findings)} potential findings.")
        for f in all_findings:
            print(f"  [{f.severity}] {f.file}:{f.line} - {f.title} ({f.cwe})")
        return

    if not token:
        print("❌ Error: GITHUB_TOKEN is required to audit pull requests.")
        sys.exit(1)

    reviewer = GitHubReviewer(token=token, repo=repo, pull_number=pull_number, commit_sha=commit_sha)

    print(f"⚡ VAJRA Security Auditor initiated for PR #{pull_number} on {repo}...")
    reviewer.set_commit_status(state="pending", description="VAJRA Multi-Stage AST & Neural Audit in progress...")

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

        local_path = Path(filename)
        file_findings = []
        file_content = ""

        # Read content
        if local_path.is_file():
            try:
                file_content = local_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        elif patch:
            file_content = patch

        # -------------------------------------------------------------
        # STAGE 1: AST & Secret Signature Rules
        # -------------------------------------------------------------
        if file_content:
            file_findings.extend(scan_content(filename, file_content))

        # -------------------------------------------------------------
        # STAGE 2: Semantic & Neural Finder
        # -------------------------------------------------------------
        if file_content:
            semantic_findings = SemanticFinder.scan_context(filename, file_content)
            file_findings.extend(semantic_findings)

        # -------------------------------------------------------------
        # STAGES 3 & 4: Neural Remediation & AST Self-Verification
        # -------------------------------------------------------------
        for f in file_findings:
            if f.severity in ("CRITICAL", "HIGH"):
                # Extract snippet around line
                snippet_lines = file_content.splitlines()[max(0, f.line - 4): min(len(file_content.splitlines()), f.line + 4)]
                snippet = "\n".join(snippet_lines)

                # Generate and verify patch
                verified_patch, is_verified = remediator.generate_verified_remediation(
                    filename=f.file,
                    line_number=f.line,
                    vulnerable_code=snippet,
                    cwe=f.cwe,
                    fallback_suggestion=f.suggestion
                )

                verification_badge = "🛡️ **AST-Verified Patch**" if is_verified else "⚠️ **Suggested Remediation**"
                comment_text = (
                    f"### ⚡ VAJRA Security Finding: {f.title} ({f.cwe})\n\n"
                    f"**Severity**: `{f.severity}`  \n"
                    f"**Verification**: {verification_badge}\n\n"
                    f"{f.description}\n\n"
                    f"```suggestion\n{verified_patch}\n```\n"
                )

                inline_comments.append({
                    "path": f.file,
                    "line": f.line,
                    "body": comment_text
                })

        findings.extend(file_findings)

    # Build response: check if triggered by an interactive slash command
    comment_text = event_data.get("comment", {}).get("body", "")
    if comment_text and any(k in comment_text.lower() for k in ("fix", "cvss", "explain", "help")):
        from vajra_bot.commands import handle_bot_command
        reply_md = handle_bot_command(comment_text, findings, len(pr_files))
    else:
        reply_md = build_audit_summary_markdown(findings, len(pr_files))

    criticals = [f for f in findings if f.severity == "CRITICAL"]
    highs = [f for f in findings if f.severity == "HIGH"]

    try:
        reviewer.post_pr_comment(reply_md)
        print("✅ Posted VAJRA response to PR thread.")
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
            description="VAJRA: Multi-stage security audit passed clean."
        )

    print("🎉 VAJRA Multi-Stage Security Audit completed successfully.")


if __name__ == "__main__":
    run_action()
