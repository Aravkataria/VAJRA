# app/tasks/queue.py

"""
Asynchronous Job & Task Scheduler for VAJRA.
"""

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional


@dataclass
class Job:
    job_id: str
    status: str
    progress: int
    created_at: str
    updated_at: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class JobManager:
    def __init__(self):
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit_job(self, task_fn: Callable[..., Any], *args, **kwargs) -> str:
        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        job = Job(
            job_id=job_id,
            status="queued",
            progress=0,
            created_at=now,
            updated_at=now,
        )

        with self._lock:
            self._jobs[job_id] = job

        def _worker():
            with self._lock:
                job.status = "running"
                job.progress = 20
                job.updated_at = datetime.now(timezone.utc).isoformat()
            try:
                result = task_fn(*args, **kwargs)
                with self._lock:
                    job.status = "completed"
                    job.progress = 100
                    job.result = result
                    job.updated_at = datetime.now(timezone.utc).isoformat()
            except Exception as exc:
                with self._lock:
                    job.status = "failed"
                    job.error = str(exc)
                    job.updated_at = datetime.now(timezone.utc).isoformat()

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return {
                "job_id": job.job_id,
                "status": job.status,
                "progress": job.progress,
                "created_at": job.created_at,
                "updated_at": job.updated_at,
                "error": job.error,
                "result": job.result,
            }


_default_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    global _default_job_manager
    if _default_job_manager is None:
        _default_job_manager = JobManager()
    return _default_job_manager