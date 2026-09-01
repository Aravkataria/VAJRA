# app/api.py

import io
import os
import shutil
import zipfile
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from app.analysis.analyst import build_default_analyst
from app.analysis.workspace_scan import scan_workspace, summarize_findings
from app.dashboard.chat_ui import CHAT_HTML
from app.dashboard.renderer import render_dashboard_html
from app.decision.engine import decide
from app.evidence.aggregator.aggregator import build_evidence, evidence_to_dicts
from app.model_independence import check_model_independence
from app.repair.patch_applier import PatchApplier
from app.repair.repairer import build_default_repairer
from app.repair.result import RepairResult
from app.report.builder import build_assurance_report, build_attempt_report, mark_finding_statuses
from app.report.html_renderer import render_assurance_report_html, render_attempt_report_html
from app.report.models import AssuranceReport, AttemptReport
from app.repository.manager import RepositoryManager
from app.storage.db import get_db
from app.verification.verifier import build_default_verifier


app = FastAPI(
    title="VAJRA",
    description="Autonomous cyber-reasoning and software repair system",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _check_api_auth(x_api_key: Optional[str] = Header(None)):
    required_key = os.environ.get("VAJRA_API_KEY")
    if required_key and x_api_key != required_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key.")


class GitHubScanRequest(BaseModel):
    url: str
    branch: Optional[str] = None


class LocalScanRequest(BaseModel):
    path: str


class LocalZipRequest(BaseModel):
    path: str


repo = RepositoryManager()
analyst = build_default_analyst()
repairer = build_default_repairer()
verifier = build_default_verifier()
patch_applier = PatchApplier()
db = get_db()
check_model_independence(analyst, repairer)

MAX_REPAIR_ATTEMPTS = int(os.environ.get("VAJRA_MAX_REPAIR_ATTEMPTS", "3"))
_last_reports: dict[str, AssuranceReport] = {}


def _tool_versions() -> dict[str, str]:
    return {
        "vajra_version": app.version,
        "analyst": type(analyst).__name__,
        "repairer_models": "+".join(type(m).__name__ for m in repairer.models),
        "verifier_stages": "+".join(type(m).__name__ for m in verifier.models),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "VAJRA",
        "repair_models": [type(m).__name__ for m in repairer.models],
        "verifier_stages": [type(m).__name__ for m in verifier.models],
    }


@app.get("/", response_class=HTMLResponse)
@app.get("/chat", response_class=HTMLResponse)
def chat_assistant():
    """ChatGPT-style conversational assistant frontend for VAJRA."""
    return HTMLResponse(content=CHAT_HTML, headers={"Cache-Control": "no-store"})


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """Metrics & audit table dashboard for VAJRA."""
    reports = db.get_all_reports()
    declined = db.get_declined_attempts()
    return HTMLResponse(content=render_dashboard_html(reports, declined))


@app.post("/scan-local")
def scan_local_folder(req: LocalScanRequest):
    """
    Directly scans and repairs a local folder on the user's computer.
    Copies into an isolated workspace and runs the complete verification pipeline.
    """
    target_dir = Path(req.path).resolve()
    if not target_dir.is_dir():
        raise HTTPException(status_code=400, detail=f"Local path '{req.path}' is not a valid directory.")

    workspace_id, workspace_path = repo.create_workspace()
    try:
        shutil.copytree(target_dir, workspace_path, dirs_exist_ok=True)
        metadata = repo.build_metadata(workspace_id, workspace_path)
        scan_result = scan_repository(workspace_id)
        return {
            "workspace_id": workspace_id,
            "source_path": str(target_dir),
            "metadata": metadata.to_dict(),
            "scan_result": scan_result,
        }
    except Exception as exc:
        repo.delete_workspace(workspace_path)
        raise HTTPException(status_code=500, detail=f"Failed to scan local folder: {exc}")


@app.get("/workspace/{workspace_id}/download-patched")
def download_patched_zip(workspace_id: str):
    """
    Downloads the cleanly repaired workspace as a ready-to-use ZIP archive.
    """
    workspace_path = repo.workspaces_dir / workspace_id
    if not workspace_path.is_dir():
        raise HTTPException(status_code=404, detail="Workspace not found.")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in workspace_path.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(workspace_path)
                zf.write(file_path, arcname=str(rel_path))

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=vajra_patched_{workspace_id[:8]}.zip"},
    )


@app.post("/upload")
async def upload_repository(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported.")

    upload_path = repo.uploads_dir / Path(file.filename).name
    try:
        with open(upload_path, "wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                destination.write(chunk)

        workspace_id, workspace_path = repo.extract_zip(upload_path)
        metadata = repo.build_metadata(workspace_id, workspace_path)
        return {
            "workspace_id": workspace_id,
            "filename": file.filename,
            "workspace": str(workspace_path),
            "metadata": metadata.to_dict(),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to process repository: {exc}")
    finally:
        try:
            upload_path.unlink(missing_ok=True)
        except OSError:
            pass


@app.post("/upload-local")
def upload_local_zip(req: LocalZipRequest):
    """
    Same as /upload, but for a ZIP file already on the local disk -- used by
    the desktop app's native file-picker dialog, which returns a filesystem
    path rather than file bytes. Avoids routing large file contents through
    the webview JS bridge.
    """
    zip_path = Path(req.path).resolve()
    if not zip_path.is_file() or zip_path.suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail=f"'{req.path}' is not a valid ZIP file.")

    try:
        workspace_id, workspace_path = repo.extract_zip(zip_path)
        metadata = repo.build_metadata(workspace_id, workspace_path)
        return {
            "workspace_id": workspace_id,
            "filename": zip_path.name,
            "workspace": str(workspace_path),
            "metadata": metadata.to_dict(),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to process repository: {exc}")


@app.post("/scan-github")
def scan_github(req: GitHubScanRequest):
    """
    Directly clones a public GitHub repository, extracts AST evidence,
    runs the Decision Engine, generates repairs and security tests,
    independently verifies them, and produces a Repair Assurance Record.
    """
    try:
        workspace_id, workspace_path = repo.clone_github_repo(req.url, req.branch)
        metadata = repo.build_metadata(workspace_id, workspace_path)
        scan_result = scan_repository(workspace_id)
        return {
            "workspace_id": workspace_id,
            "repo_url": req.url,
            "metadata": metadata.to_dict(),
            "scan_result": scan_result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to scan GitHub repository: {exc}")


@app.post("/scan-github/async")
def scan_github_async(req: GitHubScanRequest):
    """
    Submits a GitHub scan as an asynchronous background job.
    Returns immediately with a job_id that can be polled via GET /jobs/{job_id}.
    """
    from app.tasks.queue import get_job_manager

    def _task():
        workspace_id, workspace_path = repo.clone_github_repo(req.url, req.branch)
        metadata = repo.build_metadata(workspace_id, workspace_path)
        scan_result = scan_repository(workspace_id)
        return {
            "workspace_id": workspace_id,
            "repo_url": req.url,
            "metadata": metadata.to_dict(),
            "scan_result": scan_result,
        }

    job_id = get_job_manager().submit_job(_task)
    return {
        "job_id": job_id,
        "status": "queued",
        "poll_url": f"/jobs/{job_id}",
    }


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    """
    Returns the real-time status, progress, and result of a background job.
    """
    from app.tasks.queue import get_job_manager
    job = get_job_manager().get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    return job


def _finding_key(finding):
    return (
        finding.file,
        finding.vulnerability_type,
        finding.function,
        finding.message,
        finding.line,
    )


def _refresh_decision(decision, workspace_path):
    current_findings = scan_workspace(workspace_path)
    e = decision.evidence

    candidates = [
        f
        for f in current_findings
        if f.file == e.file
        and f.vulnerability_type == e.vulnerability_type
        and f.function == e.function
    ]

    if not candidates:
        return None, None

    current = min(candidates, key=lambda f: abs(f.line - e.line))
    evidence = build_evidence([current], repository=e.repository, commit=e.commit)[0]
    assessment = analyst.analyze(evidence)
    refreshed = decide(evidence, assessment)
    return refreshed, assessment


def _classify_findings(initial_findings, final_findings):
    initial = Counter(_finding_key(f) for f in initial_findings)
    final = Counter(_finding_key(f) for f in final_findings)

    resolved_keys = initial - final
    new_keys = final - initial
    remaining_keys = initial & final

    def take(findings, keys):
        result = []
        remaining = keys.copy()
        for finding in findings:
            key = _finding_key(finding)
            if remaining[key] > 0:
                result.append(finding.to_dict())
                remaining[key] -= 1
        return result

    return (
        take(initial_findings, resolved_keys),
        take(final_findings, remaining_keys),
        take(final_findings, new_keys),
    )


@app.post("/workspace/{workspace_id}/scan")
def scan_repository(workspace_id: str):
    workspace_path = repo.workspaces_dir / workspace_id
    if not workspace_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Workspace not found: {workspace_id}")

    try:
        initial_findings = scan_workspace(workspace_path)
        initial_summary = summarize_findings(initial_findings)
        initial_finding_dicts = [f.to_dict() for f in initial_findings]

        evidence = build_evidence(initial_findings, repository=workspace_id)
        assessments = analyst.analyze_all(evidence)
        decisions = [decide(e, a) for e, a in zip(evidence, assessments)]

        patches = []
        verifications = []
        applications = []
        attempts = []
        attempt_reports = []

        for original_decision in decisions:
            decision, refreshed_assessment = _refresh_decision(original_decision, workspace_path)
            if decision is None:
                attempts.append({
                    "decision": original_decision.to_dict(),
                    "status": "finding_no_longer_present",
                    "attempts": [],
                })
                attempt_reports.append(
                    build_attempt_report(
                        decision=original_decision,
                        assessment=None,
                        model_attempts=[],
                        patch=None,
                        verification_stages=[],
                        final_verification=None,
                        application=None,
                        repair_retry_count=0,
                    )
                )
                continue

            all_model_attempts = []
            patch = None
            verification = None
            stage_results = []
            current_decision = decision
            retry_count = 0

            while True:
                retry_count += 1
                patch, model_attempts = repairer.repair_with_trace(current_decision, workspace_path)
                all_model_attempts.extend(model_attempts)

                if patch is None:
                    stage_results = []
                    break

                verification, stage_results = verifier.verify_with_stages(patch, workspace_path)
                if verification.verified:
                    break

                if current_decision.route != "reasoning" or retry_count >= MAX_REPAIR_ATTEMPTS:
                    break

                new_feedback = (
                    f"Attempt {retry_count} was rejected by verification "
                    f"({verification.method}): {verification.reason}"
                )
                accumulated_feedback = (
                    f"{current_decision.feedback}\n{new_feedback}"
                    if current_decision.feedback
                    else new_feedback
                )
                current_decision = replace(
                    current_decision,
                    feedback=accumulated_feedback,
                )

            attempts.append({
                "decision": decision.to_dict(),
                "assessment": refreshed_assessment.to_dict() if refreshed_assessment else None,
                "attempts": [a.to_dict() for a in all_model_attempts],
                "repair_retry_count": retry_count,
            })

            application = None
            if patch is not None and verification is not None and verification.verified:
                application = patch_applier.apply(patch, workspace_path)

            att_report = build_attempt_report(
                decision=current_decision,
                assessment=refreshed_assessment,
                model_attempts=all_model_attempts,
                patch=patch,
                verification_stages=stage_results,
                final_verification=verification,
                application=application,
                repair_retry_count=retry_count,
            )
            attempt_reports.append(att_report)

            if patch is None:
                continue

            patches.append(patch)
            verifications.append(verification)

            if not verification.verified:
                continue

            applications.append(application)

        final_findings = scan_workspace(workspace_path)
        final_summary = summarize_findings(final_findings)
        final_finding_dicts = [f.to_dict() for f in final_findings]

        resolved_findings, remaining_findings, new_findings = _classify_findings(
            initial_findings,
            final_findings,
        )

        verified_count = sum(1 for v in verifications if v.verified)
        applied_count = sum(1 for a in applications if a.applied)

        if not initial_findings:
            status = "clean"
        elif not final_findings:
            status = "fully_repaired"
        elif resolved_findings:
            status = "partially_repaired"
        else:
            status = "no_repairs"

        if new_findings:
            status = (
                "partially_repaired_with_new_findings"
                if resolved_findings
                else "repair_introduced_findings"
            )

        repair_result = RepairResult(
            status=status,
            initial_findings=len(initial_findings),
            patches_proposed=len(patches),
            patches_verified=verified_count,
            patches_applied=applied_count,
            findings_resolved=len(resolved_findings),
            findings_remaining=len(remaining_findings),
            new_findings=len(new_findings),
            attempts=attempts,
            applications=[a.to_dict() for a in applications],
            resolved_findings=resolved_findings,
            remaining_findings=remaining_findings,
            new_findings_detail=new_findings,
        )

        initial_keys = {(f.file, f.vulnerability_type, f.function, f.line) for f in initial_findings}
        final_keys = {(f.file, f.vulnerability_type, f.function, f.line) for f in final_findings}
        mark_finding_statuses(
            attempt_reports,
            resolved_keys=initial_keys - final_keys,
            remaining_keys=initial_keys & final_keys,
        )
        assurance_report = build_assurance_report(
            workspace_id=workspace_id,
            attempt_reports=attempt_reports,
            initial_findings_count=len(initial_findings),
            final_findings_count=len(final_findings),
            tool_versions=_tool_versions(),
        )

        _last_reports[workspace_id] = assurance_report
        rendered_html = render_assurance_report_html(assurance_report)
        db.record_assurance_report(assurance_report, rendered_html)
        for att in attempt_reports:
            db.record_attempt(att, workspace_id)

        return {
            "workspace_id": workspace_id,
            "summary": initial_summary,
            "findings": initial_finding_dicts,
            "evidence": evidence_to_dicts(evidence),
            "assessments": [a.to_dict() for a in assessments],
            "decisions": [d.to_dict() for d in decisions],
            "patches": [p.to_dict() for p in patches],
            "verifications": [v.to_dict() for v in verifications],
            "applications": [a.to_dict() for a in applications],
            "repair_attempts": attempts,
            "post_repair": {
                "summary": final_summary,
                "findings": final_finding_dicts,
            },
            "repair_result": repair_result.to_dict(),
            "assurance_report": assurance_report.to_dict(),
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"VAJRA scan failed: {exc}")


@app.get("/workspace/{workspace_id}/report.json")
def get_assurance_report_json(workspace_id: str):
    report = _last_reports.get(workspace_id)
    if report is not None:
        return report.to_dict()

    db_report = db.get_assurance_report(workspace_id)
    if db_report is not None:
        return db_report

    raise HTTPException(
        status_code=404,
        detail=f"No Repair Assurance Report available for workspace {workspace_id}. Run a scan first.",
    )


@app.get("/workspace/{workspace_id}/report.html", response_class=HTMLResponse)
def get_assurance_report_html(workspace_id: str):
    report = _last_reports.get(workspace_id)
    if report is not None:
        return HTMLResponse(content=render_assurance_report_html(report))

    html_content = db.get_assurance_report_html(workspace_id)
    if html_content is not None:
        return HTMLResponse(content=html_content)

    raise HTTPException(
        status_code=404,
        detail=f"No Repair Assurance Report available for workspace {workspace_id}. Run a scan first.",
    )


@app.get("/attempts/{attempt_id}")
def get_attempt_json(attempt_id: str):
    att = db.get_attempt(attempt_id)
    if att is None:
        raise HTTPException(status_code=404, detail=f"Attempt {attempt_id} not found.")
    return att


@app.get("/attempts/{attempt_id}/html", response_class=HTMLResponse)
def get_attempt_html(attempt_id: str):
    att_dict = db.get_attempt(attempt_id)
    if att_dict is None:
        raise HTTPException(status_code=404, detail=f"Attempt {attempt_id} not found.")
    
    att_obj = AttemptReport(
        attempt_id=att_dict["attempt_id"],
        generated_at=att_dict["generated_at"],
        file=att_dict["finding"]["file"],
        line=att_dict["finding"]["line"],
        function=att_dict["finding"]["function"],
        vulnerability_type=att_dict["finding"]["vulnerability_type"],
        severity=att_dict["finding"]["severity"],
        finding_message=att_dict["finding"]["message"],
        assessment=att_dict.get("assessment"),
        decision_route=att_dict["decision"]["route"],
        decision_reason=att_dict["decision"]["reason"],
        deterministic_fix=att_dict["decision"]["deterministic_fix"],
        repair_retry_count=att_dict["decision"]["repair_retry_count"],
        retry_feedback_used=att_dict["decision"]["retry_feedback_used"],
        model_attempts=att_dict.get("model_attempts", []),
        patch_diff=att_dict["patch"]["diff"] if att_dict.get("patch") else None,
        patch_description=att_dict["patch"]["description"] if att_dict.get("patch") else None,
        patch_strategy=att_dict["patch"]["strategy"] if att_dict.get("patch") else None,
        patch_confidence=att_dict["patch"]["confidence"] if att_dict.get("patch") else None,
        original_sha256=att_dict["patch"]["original_sha256"] if att_dict.get("patch") else None,
        patched_sha256=att_dict["patch"]["patched_sha256"] if att_dict.get("patch") else None,
        verification_stages=att_dict["verification"]["stages"],
        final_verification_method=att_dict["verification"]["final_method"],
        final_verification_passed=att_dict["verification"]["final_passed"],
        final_verification_reason=att_dict["verification"]["final_reason"],
        applied=att_dict["application"]["applied"],
        application_reason=att_dict["application"]["reason"],
        finding_status=att_dict.get("finding_status"),
        outcome=att_dict["outcome"],
        outcome_reason=att_dict["outcome_reason"],
        limitations=att_dict.get("limitations", []),
    )
    return HTMLResponse(content=render_attempt_report_html(att_obj))


@app.get("/history/{vulnerability_type}")
def get_failure_history(vulnerability_type: str, file: Optional[str] = None):
    return db.get_failure_memory(vulnerability_type, file)


@app.delete("/workspace/{workspace_id}")
def delete_workspace(workspace_id: str):
    workspace_path = repo.workspaces_dir / workspace_id
    if not workspace_path.exists():
        raise HTTPException(status_code=404, detail=f"Workspace not found: {workspace_id}")
    try:
        repo.delete_workspace(workspace_path)
        _last_reports.pop(workspace_id, None)
        return {"status": "deleted", "workspace_id": workspace_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete workspace: {exc}")