# tests/test_unified_pipeline.py

import io
import json
import zipfile
from pathlib import Path
from fastapi.testclient import TestClient

import app.api as api_module
from app.services.cache_manager import get_cache
from app.services.model_manager import get_model_manager

VULN_CODE = """
import yaml

def load_data(raw):
    return yaml.load(raw)
"""


def _make_zip(filename: str = "app.py", code: str = VULN_CODE) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, code)
    buf.seek(0)
    return buf.getvalue()


def test_unified_analyze_endpoint():
    client = TestClient(api_module.app)

    # 1. Upload repository
    zip_bytes = _make_zip()
    upload_res = client.post("/upload", files={"file": ("repo.zip", zip_bytes, "application/zip")})
    assert upload_res.status_code == 200
    workspace_id = upload_res.json()["workspace_id"]

    # 2. Check cookies set
    assert "vajra_session" in upload_res.cookies

    # 3. Call unified analysis endpoint
    analyze_res = client.post(f"/workspace/{workspace_id}/analyze")
    assert analyze_res.status_code == 200
    data = analyze_res.json()

    assert data["workspace_id"] == workspace_id
    assert "summary" in data
    assert "findings" in data
    assert "evidence" in data
    assert "decisions" in data
    assert "assurance_report" in data
    assert data["cached"] is False

    # 4. Verify workspace directory isolation
    workspace_dir = Path("workspaces") / workspace_id
    assert (workspace_dir / "evidence" / "evidence.json").is_file()
    assert (workspace_dir / "findings" / "initial_findings.json").is_file()
    assert (workspace_dir / "reports" / "assurance_report.json").is_file()

    # 5. After initial repair, second call analyzes the clean state and caches it
    res2 = client.post(f"/workspace/{workspace_id}/analyze")
    assert res2.status_code == 200
    
    # 6. Third identical call on unchanged repository is served instantly from cache
    res3 = client.post(f"/workspace/{workspace_id}/analyze")
    assert res3.status_code == 200
    assert res3.json()["cached"] is True

    # 7. Delete workspace and verify cache cleanup
    del_res = client.delete(f"/workspace/{workspace_id}")
    assert del_res.status_code == 200
    assert not workspace_dir.exists()


def test_health_endpoint_contract():
    client = TestClient(api_module.app)
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()

    # Backward compatibility keys
    assert data["status"] == "ok"
    assert data["service"] == "VAJRA"
    assert "repair_models" in data
    assert "verifier_stages" in data

    # Enhanced production keys
    assert "model1" in data
    assert data["model1"]["version"]
    assert "model2" in data
    assert "cache" in data
    assert data["cache"]["status"] == "available"
    assert "concurrency" in data
    assert data["concurrency"]["max_concurrent"] >= 1


def test_rate_limiting_guard():
    client = TestClient(api_module.app)
    # Perform requests to ensure rate limit headers are present
    res = client.get("/health")
    assert res.status_code == 200
    assert "X-RateLimit-Limit" in res.headers
    assert "X-RateLimit-Remaining" in res.headers
    assert res.headers["X-Content-Type-Options"] == "nosniff"
