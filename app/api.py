# app/api.py

import asyncio
from contextlib import asynccontextmanager
import hashlib
import io
import json
import os
import shutil
import threading
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from app.analysis.analyst import build_default_analyst
from app.analysis.workspace_scan import scan_workspace, summarize_findings
from app.analysis.git_archaeologist import GitArchaeologist
from app.analysis.dependency_reachability import DependencyReachabilityAnalyzer
from app.verification.exploit_harness import ExploitHarness
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
from app.services.cache_manager import get_cache
from app.services.model_manager import get_model_manager
from app.storage.db import get_db
from app.verification.verifier import build_default_verifier

# Application-level singletons
model_manager = get_model_manager()
cache = get_cache()
repo = RepositoryManager()
patch_applier = PatchApplier()
db = get_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI Lifespan: Loads Model 1 & Model 2 ONCE at server startup
    and maintains them in memory across all requests.
    """
    model_manager.initialize()
    yield
    model_manager.shutdown()


app = FastAPI(
    title="VAJRA",
    description="Autonomous cyber-reasoning and software repair system",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting & Production Guardrails
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS_PER_WINDOW = int(os.environ.get("VAJRA_RATE_LIMIT", "120"))
_ip_request_history: Dict[str, List[float]] = {}
_history_lock = threading.Lock()


@app.middleware("http")
async def production_security_and_rate_limit(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()

    # Rate Limiting (Sliding Window)
    with _history_lock:
        timestamps = _ip_request_history.setdefault(client_ip, [])
        _ip_request_history[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        current_count = len(_ip_request_history[client_ip])

        if current_count >= MAX_REQUESTS_PER_WINDOW:
            oldest = _ip_request_history[client_ip][0] if _ip_request_history[client_ip] else now
            reset_in = max(1, int(RATE_LIMIT_WINDOW - (now - oldest)))
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Allowed {MAX_REQUESTS_PER_WINDOW} requests per {RATE_LIMIT_WINDOW}s.",
                    "code": "RATE_LIMIT_EXCEEDED",
                },
                headers={
                    "X-RateLimit-Limit": str(MAX_REQUESTS_PER_WINDOW),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_in),
                    "Retry-After": str(reset_in),
                },
            )
        _ip_request_history[client_ip].append(now)
        remaining = MAX_REQUESTS_PER_WINDOW - len(_ip_request_history[client_ip])

    response: Response = await call_next(request)

    # Security & Rate-limiting headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-RateLimit-Limit"] = str(MAX_REQUESTS_PER_WINDOW)
    response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))

    # User Workspace Isolation Cookie
    if "vajra_session" not in request.cookies:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            key="vajra_session",
            value=session_id,
            httponly=True,
            samesite="lax",
            max_age=86400 * 30,
        )

    return response


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


class AnalysisOptions(BaseModel):
    skip_cache: bool = False
    max_repair_attempts: Optional[int] = None


# Backward-compatible references to shared models
analyst = model_manager.analyst
repairer = model_manager.repairer
verifier = model_manager.verifier
check_model_independence(analyst, repairer)

MAX_REPAIR_ATTEMPTS = int(os.environ.get("VAJRA_MAX_REPAIR_ATTEMPTS", "3"))
_last_reports: dict[str, AssuranceReport] = {}

# In-memory progress tracking for active workspace analyses
_workspace_progress: Dict[str, Dict[str, Any]] = {}
_progress_lock = threading.Lock()


def _update_progress(workspace_id: str, stage: str, message: str, percent: int):
    with _progress_lock:
        _workspace_progress[workspace_id] = {
            "stage": stage,
            "message": message,
            "percent": percent,
            "timestamp": time.time(),
        }


def _tool_versions() -> dict[str, str]:
    return {
        "vajra_version": app.version,
        "analyst": type(model_manager.analyst.model).__name__,
        "model1_version": model_manager.model1_version,
        "model2_version": model_manager.model2_version,
        "repairer_models": "+".join(type(m).__name__ for m in model_manager.repairer.models),
        "verifier_stages": "+".join(type(m).__name__ for m in model_manager.verifier.models),
    }


@app.get("/health")
def health():
    telemetry = model_manager.get_health_details()
    cache_stats = cache.stats()
    return {
        "status": "ok",
        "service": "VAJRA",
        "version": app.version,
        "backend": "ready",
        "repair_models": telemetry["model2"]["implementations"],
        "verifier_stages": [type(m).__name__ for m in model_manager.verifier.models],
        "model1": telemetry["model1"],
        "model2": telemetry["model2"],
        "cache": {
            "status": "available",
            **cache_stats,
        },
        "concurrency": telemetry["concurrency"],
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
    current_analyst = analyst if analyst is not None else model_manager.analyst
    if current_analyst is model_manager.analyst:
        assessment = model_manager.analyze(evidence)
    else:
        assessment = current_analyst.analyze(evidence)
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


def execute_analysis_pipeline(
    workspace_id: str,
    skip_cache: bool = False,
    max_repair_attempts: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Unified end-to-end VAJRA analysis and repair pipeline.
    Stateless models, isolated workspace artifacts, live progress reporting,
    and deterministic stage-aware caching.
    """
    workspace_path = repo.workspaces_dir / workspace_id
    if not workspace_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Workspace not found: {workspace_id}")

    # Set up isolated workspace directory layout
    dirs = repo.ensure_workspace_layout(workspace_path)
    effective_max_attempts = max_repair_attempts if max_repair_attempts is not None else MAX_REPAIR_ATTEMPTS

    _update_progress(workspace_id, "indexing", "Indexing repository files & language detection", 10)

    try:
        # Check cache if not skipped
        hasher = hashlib.sha256()
        internal_subdirs = {"evidence", "findings", "patches", "verification", "reports", ".git"}
        for f in sorted(workspace_path.rglob("*")):
            if f.is_file():
                parts = f.relative_to(workspace_path).parts
                if not any(p in internal_subdirs for p in parts[:-1]):
                    hasher.update(str(f.relative_to(workspace_path)).encode())
                    hasher.update(f.read_bytes()[:100000])
        repo_hash = hasher.hexdigest()

        cache_key = cache.compute_key(
            operation="full_pipeline",
            input_data=repo_hash,
            model_version=f"{model_manager.model1_version}+{model_manager.model2_version}",
            analyzer_version=model_manager.analyzer_version,
            config={"max_repair_attempts": effective_max_attempts},
            workspace_id=workspace_id,
        )

        if not skip_cache:
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                _update_progress(workspace_id, "complete", "Retrieved verified analysis from cache", 100)
                cached_copy = dict(cached_result)
                cached_copy["cached"] = True
                return cached_copy

        # Stage 1: Static AST Analysis
        _update_progress(workspace_id, "static_analysis", "Static AST analysis in progress", 25)
        initial_findings = scan_workspace(workspace_path)
        initial_summary = summarize_findings(initial_findings)
        initial_finding_dicts = [f.to_dict() for f in initial_findings]

        # Stage 2: Evidence Aggregation
        _update_progress(workspace_id, "evidence", "Collecting and normalizing AST evidence", 40)
        evidence = build_evidence(initial_findings, repository=workspace_id)

        current_analyst = analyst if analyst is not None else model_manager.analyst
        current_repairer = repairer if repairer is not None else model_manager.repairer
        current_verifier = verifier if verifier is not None else model_manager.verifier

        # Stage 3: Model 1 Security Analyst Evaluation
        _update_progress(workspace_id, "ai_analyst", "Model 1 (Security Analyst) triage active", 55)
        if current_analyst is model_manager.analyst:
            assessments = model_manager.analyze_all(evidence)
        else:
            assessments = current_analyst.analyze_all(evidence)

        # Stage 4: Decision Engine
        _update_progress(workspace_id, "decision", "Evaluating Decision Engine routes", 70)
        decisions = [decide(e, a) for e, a in zip(evidence, assessments)]

        patches = []
        verifications = []
        applications = []
        attempts = []
        attempt_reports = []

        # Stage 5: Model 2 Patch Generation & Verification Loop
        _update_progress(workspace_id, "repair", "Generating patches and running verification", 85)
        for idx, original_decision in enumerate(decisions, start=1):
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
                if current_repairer is model_manager.repairer:
                    patch, model_attempts = model_manager.repair_with_trace(current_decision, workspace_path)
                else:
                    patch, model_attempts = current_repairer.repair_with_trace(current_decision, workspace_path)
                all_model_attempts.extend(model_attempts)

                if patch is None:
                    stage_results = []
                    break

                if current_verifier is model_manager.verifier:
                    verification, stage_results = model_manager.verify_with_stages(patch, workspace_path)
                else:
                    verification, stage_results = current_verifier.verify_with_stages(patch, workspace_path)
                if verification.verified:
                    break

                if current_decision.route != "reasoning" or retry_count >= effective_max_attempts:
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
                # Persist patch diff in workspace patches directory
                try:
                    patch_file = dirs["patches"] / f"patch_{idx:03d}.diff"
                    patch_file.write_text(patch.diff or "", encoding="utf-8")
                except Exception:
                    pass

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

        # Stage 6: Post-Repair Re-Scan
        _update_progress(workspace_id, "post_scan", "Re-scanning workspace and classifying findings", 95)
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

        # Run AST Dependency Reachability
        dep_findings = DependencyReachabilityAnalyzer().analyze_workspace_dependencies(str(workspace_path))
        dep_dicts = [d.__dict__ for d in dep_findings]

        result_payload = {
            "workspace_id": workspace_id,
            "summary": initial_summary,
            "findings": initial_finding_dicts,
            "evidence": evidence_to_dicts(evidence),
            "assessments": [a.to_dict() for a in assessments],
            "decisions": [d.to_dict() for d in decisions],
            "patches": [p.to_dict() for p in patches],
            "verifications": [v.to_dict() for v in verifications],
            "applications": [a.to_dict() for a in applications],
            "dependencies": dep_dicts,
            "repair_attempts": attempts,
            "post_repair": {
                "summary": final_summary,
                "findings": final_finding_dicts,
            },
            "repair_result": repair_result.to_dict(),
            "assurance_report": assurance_report.to_dict(),
            "cached": False,
        }

        # Persist artifacts into user's isolated workspace directories
        try:
            (dirs["evidence"] / "evidence.json").write_text(json.dumps(result_payload["evidence"], indent=2), encoding="utf-8")
            (dirs["findings"] / "initial_findings.json").write_text(json.dumps(result_payload["findings"], indent=2), encoding="utf-8")
            (dirs["findings"] / "post_repair_findings.json").write_text(json.dumps(result_payload["post_repair"], indent=2), encoding="utf-8")
            (dirs["reports"] / "assurance_report.json").write_text(json.dumps(result_payload["assurance_report"], indent=2), encoding="utf-8")
            (dirs["reports"] / "assurance_report.html").write_text(rendered_html, encoding="utf-8")
        except Exception:
            pass

        # Save to deterministic cache
        cache.set(cache_key, result_payload, workspace_id=workspace_id)
        _update_progress(workspace_id, "complete", "Analysis and verification complete", 100)

        return result_payload

    except HTTPException:
        _update_progress(workspace_id, "failed", "Analysis failed", 0)
        raise
    except Exception as exc:
        _update_progress(workspace_id, "failed", str(exc), 0)
        raise HTTPException(status_code=500, detail=f"VAJRA scan failed: {exc}")


@app.post("/workspace/{workspace_id}/scan")
def scan_repository(workspace_id: str):
    """Legacy backward-compatible endpoint triggering workspace scan."""
    return execute_analysis_pipeline(workspace_id)


@app.post("/workspace/{workspace_id}/analyze")
def analyze_workspace(workspace_id: str, options: Optional[AnalysisOptions] = None):
    """
    Unified end-to-end analysis endpoint for single frontend call.
    Supports options: skip_cache, max_repair_attempts.
    """
    skip = options.skip_cache if options else False
    max_att = options.max_repair_attempts if options else None
    return execute_analysis_pipeline(workspace_id, skip_cache=skip, max_repair_attempts=max_att)


@app.get("/workspace/{workspace_id}/analyze/progress")
async def stream_analysis_progress(workspace_id: str):
    """
    Server-Sent Events (SSE) streaming progress endpoint.
    Frontend connects to show live pipeline status without heavy polling.
    """
    async def event_generator():
        last_percent = -1
        for _ in range(120):  # Stream for up to 60s
            with _progress_lock:
                progress_info = _workspace_progress.get(workspace_id)

            if progress_info:
                if progress_info["percent"] != last_percent:
                    last_percent = progress_info["percent"]
                    yield f"data: {json.dumps(progress_info)}\n\n"

                if progress_info["percent"] >= 100 or progress_info["stage"] in ("complete", "failed"):
                    break

            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


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