# app/launcher.py

"""
VAJRA · Universal Cross-Platform Launcher & Self-Updating Engine.

Supported Operating Systems: macOS, Windows, Linux.
Modes:
  - vajra (default)         : Launches native desktop GUI application.
  - vajra --web             : Launches local FastAPI web server & opens browser.
  - vajra scan <path/url>   : Runs headless terminal security scan and repair.
  - vajra update            : Checks for updates and applies atomic self-update.
  - vajra version           : Prints current version and environment status.
"""

import sys
import os
import json
import shutil
import urllib.request
import urllib.error
import argparse
from pathlib import Path

__version__ = "2.4.0"
REPO_OWNER = "Aravkataria"
REPO_NAME = "VAJRA-test"
GITHUB_API_COMMITS = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits/main"
GITHUB_ZIP_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/archive/refs/heads/main.zip"


def get_app_root() -> Path:
    """Returns the root directory of the VAJRA installation."""
    return Path(__file__).resolve().parent.parent


def check_for_updates(quiet: bool = False) -> bool:
    """
    Checks if a newer version or commit is available on GitHub.
    Returns True if an update is available and applied.
    """
    if not quiet:
        print("[VAJRA] Checking for updates...")

    try:
        req = urllib.request.Request(
            GITHUB_API_COMMITS,
            headers={"User-Agent": "VAJRA-SelfUpdater", "Accept": "application/vnd.github.v3+json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                remote_sha = data.get("sha", "")[:7]
                
                version_file = get_app_root() / ".version_sha"
                local_sha = ""
                if version_file.exists():
                    local_sha = version_file.read_text(encoding="utf-8").strip()

                if remote_sha and remote_sha != local_sha:
                    if not quiet:
                        print(f"[VAJRA] New update found (Commit: {remote_sha}). Applying update...")
                    return apply_update(remote_sha)
                else:
                    if not quiet:
                        print(f"[VAJRA] VAJRA is already up-to-date (v{__version__} @ {local_sha or 'latest'}).")
                    return False
    except Exception as e:
        if not quiet:
            print(f"[VAJRA] Note: Could not check updates ({e}). Continuing with current version.")
        return False
    return False


def apply_update(new_sha: str) -> bool:
    """
    Downloads the latest archive from GitHub and atomically updates the installation.
    """
    app_root = get_app_root()
    temp_zip = app_root / ".update_temp.zip"
    temp_extract = app_root / ".update_extracted"

    try:
        print("[VAJRA] Downloading latest update archive...")
        urllib.request.urlretrieve(GITHUB_ZIP_URL, str(temp_zip))

        print("[VAJRA] Extracting update files...")
        shutil.unpack_archive(str(temp_zip), str(temp_extract))

        # The extracted folder is typically VAJRA-test-main
        extracted_root = None
        for item in temp_extract.iterdir():
            if item.is_dir() and item.name.startswith(f"{REPO_NAME}-"):
                extracted_root = item
                break

        if not extracted_root:
            extracted_root = temp_extract

        # Copy updated files into app_root
        for src_path in extracted_root.rglob("*"):
            rel_path = src_path.relative_to(extracted_root)
            dest_path = app_root / rel_path

            # Don't overwrite virtual environment or git state
            if "venv" in rel_path.parts or ".git" in rel_path.parts:
                continue

            if src_path.is_dir():
                dest_path.mkdir(parents=True, exist_ok=True)
            else:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src_path), str(dest_path))

        # Save new commit SHA
        (app_root / ".version_sha").write_text(new_sha, encoding="utf-8")

        # Cleanup
        if temp_zip.exists():
            temp_zip.unlink()
        if temp_extract.exists():
            shutil.rmtree(str(temp_extract), ignore_errors=True)

        print("[VAJRA] Update successfully applied! Restarting VAJRA...\n")
        return True

    except Exception as e:
        print(f"[VAJRA] Update failed: {e}")
        if temp_zip.exists():
            temp_zip.unlink()
        if temp_extract.exists():
            shutil.rmtree(str(temp_extract), ignore_errors=True)
        return False


def launch_desktop():
    """Launches the native pywebview desktop interface."""
    from app.desktop_app import main as desktop_main
    desktop_main()


def launch_web(port: int = 8000, host: str = "127.0.0.1"):
    """Launches the FastAPI backend and opens the browser."""
    import webbrowser
    import uvicorn

    url = f"http://{host}:{port}/chat"
    print(f"\n[VAJRA] Launching local web dashboard at: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    from app.api import app as fastapi_app
    uvicorn.run(fastapi_app, host=host, port=port, log_level="info")


def run_cli_scan(target: str, output_json: bool = False):
    """Executes a headless terminal scan and verification on a target path."""
    from app.analysis.workspace_scan import scan_workspace
    from app.evidence.aggregator.aggregator import build_evidence
    from app.analysis.analyst import build_default_analyst
    from app.decision.engine import decide
    from app.repair.repairer import build_default_repairer

    target_path = Path(target).resolve()
    print(f"\n[VAJRA CLI] Starting autonomous security scan on: {target_path}")

    if not target_path.exists():
        print(f"[VAJRA ERROR] Target directory does not exist: {target_path}")
        sys.exit(1)

    findings = scan_workspace(target_path)
    analyst = build_default_analyst()
    repairer = build_default_repairer()

    evidence_list = build_evidence(findings, repository=target_path.name, commit="HEAD")
    patches = []

    for ev in evidence_list:
        assessment = analyst.analyze(ev)
        decision = decide(ev, assessment)
        if decision.route != "none":
            patch = repairer.repair(decision, str(target_path))
            if patch:
                patches.append(patch)

    if output_json:
        result = {
            "version": __version__,
            "target": str(target_path),
            "findings_count": len(findings),
            "patches_count": len(patches),
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "type": f.vulnerability_type,
                    "severity": f.severity,
                    "message": f.message
                }
                for f in findings
            ],
            "patches": [
                {
                    "file": p.file,
                    "line": p.line,
                    "diff": p.diff
                }
                for p in patches
            ]
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"\n--- SCAN RESULTS ---")
        print(f"Total Vulnerabilities Detected: {len(findings)}")
        print(f"Total Minimal Repairs Synthesized: {len(patches)}\n")

        for idx, f in enumerate(findings, 1):
            print(f"[{idx}] {f.severity.upper()} - {f.vulnerability_type}")
            print(f"    Location: {f.file}:{f.line}")
            print(f"    Message:  {f.message}")

        if patches:
            print(f"\n--- SYNTHESIZED REPAIR DIFFS ---")
            for p in patches:
                print(f"File: {p.file} (Line {p.line})")
                print(p.diff)
                print("-" * 40)


def main():
    parser = argparse.ArgumentParser(
        prog="vajra",
        description="VAJRA: Autonomous Cyber-Reasoning & Software Repair System (macOS / Windows / Linux)"
    )
    parser.add_argument("--desktop", action="store_true", help="Launch native desktop GUI (default)")
    parser.add_argument("--web", action="store_true", help="Launch local web dashboard in browser")
    parser.add_argument("--port", type=int, default=8000, help="Port for web dashboard (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host for web dashboard (default: 127.0.0.1)")
    parser.add_argument("--scan", type=str, help="Scan a local folder and output findings")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--benchmark", action="store_true", help="Run the empirical 50-fixture benchmark suite and output telemetry")
    parser.add_argument("--update", action="store_true", help="Check and install the latest release update")
    parser.add_argument("--version", action="store_true", help="Display version and system information")

    parser.add_argument("target", nargs="?", default=None, help="Target directory to scan (optional)")

    args = parser.parse_args()

    if args.version:
        print(f"VAJRA version {__version__} ({sys.platform})")
        print(f"Python: {sys.version.split()[0]}")
        print(f"Install Root: {get_app_root()}")
        return

    if args.update:
        updated = check_for_updates(quiet=False)
        if updated:
            print("[VAJRA] Launching updated version...")
            os.execv(sys.executable, [sys.executable, "-m", "app.launcher"] + [a for a in sys.argv[1:] if a != "--update"])
        return

    # Background update check (skip if scanning or disabled)
    if not args.no_update_check and not args.scan and not args.target:
        updated = check_for_updates(quiet=True)
        if updated:
            os.execv(sys.executable, [sys.executable, "-m", "app.launcher"] + sys.argv[1:])

    if args.benchmark:
        from tests.benchmark_suite import run_benchmark
        run_benchmark()
        return

    # Command routing
    if args.scan or args.target:
        target = args.scan or args.target
        run_cli_scan(target, output_json=args.json)
    elif args.web:
        launch_web(port=args.port, host=args.host)
    else:
        # Default: Native Desktop App
        launch_desktop()


if __name__ == "__main__":
    main()
