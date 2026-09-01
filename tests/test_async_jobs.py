# tests/test_async_jobs.py

import time
from app.tasks.queue import JobManager


def test_job_manager_async_execution():
    jm = JobManager()

    def dummy_task(x: int):
        time.sleep(0.05)
        return {"result": x * 2}

    job_id = jm.submit_job(dummy_task, 21)
    status_initial = jm.get_job(job_id)
    assert status_initial["status"] in ("queued", "running")

    time.sleep(0.15)
    status_done = jm.get_job(job_id)
    assert status_done["status"] == "completed"
    assert status_done["progress"] == 100
    assert status_done["result"] == {"result": 42}