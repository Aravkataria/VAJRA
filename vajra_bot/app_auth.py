"""
VAJRA GitHub App Autonomous Authentication & Webhook Handler
Allows VAJRA-Bot (App ID: 5075351) to autonomously audit PRs and reply to comments
without requiring any YAML workflow files in target repositories.
Lead Engineer: Arav Kataria
"""

import os
import time
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

from vajra_bot.scanner import scan_content, Finding
from vajra_bot.finder import SemanticFinder
from vajra_bot.remediator import ModelRemediator
from vajra_bot.reviewer import GitHubReviewer, build_audit_summary_markdown
from vajra_bot.commands import handle_bot_command

APP_ID = os.environ.get("GITHUB_APP_ID", "5075351")


def generate_app_jwt(app_id: str, private_key_pem: str) -> Optional[str]:
    """Generates an RS256 signed JWT valid for 10 minutes to authenticate as the GitHub App."""
    try:
        import jwt
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": str(app_id)
        }
        token = jwt.encode(payload, private_key_pem, algorithm="RS256")
        return token if isinstance(token, str) else token.decode("utf-8")
    except Exception as e:
        print(f"⚠️ JWT generation error: {e}")
        return None


def get_installation_access_token(installation_id: int, jwt_token: str) -> Optional[str]:
    """Exchanges App JWT for an installation access token valid for the target repo."""
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VAJRA-Bot-App"
    }
    req = urllib.request.Request(url, data=b"", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("token")
    except Exception as e:
        print(f"⚠️ Error obtaining installation token for {installation_id}: {e}")
        return None


def handle_github_app_webhook(payload: Dict[str, Any], event_type: str) -> Dict[str, Any]:
    """
    Autonomous webhook processor that audits PRs and replies to comments as VAJRA-Bot[bot].
    Zero YAML files needed in target repositories!
    """
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY") or os.environ.get("GITHUB_PRIVATE_KEY")
    app_id = os.environ.get("GITHUB_APP_ID", APP_ID)

    if not private_key:
        return {
            "status": "acknowledged",
            "note": "GITHUB_APP_PRIVATE_KEY not configured on server. Add it to Space secrets to enable autonomous mode."
        }

    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    if not installation_id:
        return {"status": "skipped", "reason": "No installation ID found in payload."}

    # 1. Authenticate with GitHub as VAJRA-Bot
    jwt_token = generate_app_jwt(app_id, private_key)
    if not jwt_token:
        return {"status": "error", "reason": "Could not sign JWT with private key."}

    token = get_installation_access_token(installation_id, jwt_token)
    if not token:
        return {"status": "error", "reason": "Could not acquire installation access token."}

    repo_full_name = payload.get("repository", {}).get("full_name")

    # 2. Handle Pull Request Events
    if event_type == "pull_request":
        action = payload.get("action")
        if action not in ("opened", "synchronize", "reopened"):
            return {"status": "skipped", "reason": f"PR action '{action}' does not require audit."}

        pr = payload.get("pull_request", {})
        pull_number = pr.get("number")
        commit_sha = pr.get("head", {}).get("sha")

        reviewer = GitHubReviewer(token=token, repo=repo_full_name, pull_number=pull_number, commit_sha=commit_sha)
        reviewer.set_commit_status(state="pending", description="VAJRA-Bot: Autonomous security audit running...")

        pr_files = reviewer.get_pr_files()
        findings: List[Finding] = []
        remediator = ModelRemediator()

        for f in pr_files:
            filename = f.get("filename", "")
            patch = f.get("patch", "")
            if not patch or any(part in filename.lower() for part in ("/tests/", "tests/", "test_", "_test.")):
                continue

            sec = scan_content(filename, patch)
            sec.extend(SemanticFinder.scan_context(filename, patch))
            findings.extend(sec)

        summary_md = build_audit_summary_markdown(findings, len(pr_files))
        criticals = [f for f in findings if f.severity == "CRITICAL"]

        try:
            reviewer.post_pr_comment(summary_md)
            state = "failure" if criticals else "success"
            desc = f"VAJRA: {len(criticals)} critical vulnerabilities detected!" if criticals else "VAJRA: Security audit passed clean."
            reviewer.set_commit_status(state=state, description=desc)
            return {"status": "completed", "pr": pull_number, "findings": len(findings)}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    # 3. Handle Issue & PR Comments (@vajra commands)
    if event_type == "issue_comment":
        action = payload.get("action")
        if action != "created":
            return {"status": "skipped", "reason": "Only new comments processed."}

        comment = payload.get("comment", {})
        comment_body = comment.get("body", "")
        if "@vajra" not in comment_body.lower():
            return {"status": "skipped", "reason": "No @vajra mention in comment."}

        issue = payload.get("issue", {})
        pull_number = issue.get("number")

        reviewer = GitHubReviewer(token=token, repo=repo_full_name, pull_number=pull_number)
        reply = handle_bot_command(comment_body, [], 0)
        reviewer.post_pr_comment(reply)
        return {"status": "replied", "command": comment_body[:30]}

    return {"status": "ignored", "event": event_type}
