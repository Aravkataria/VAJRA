# tests/test_error_handlers.py

import pytest
from fastapi.testclient import TestClient
from app.api import app, VAJRA_SECRET_KEY

client = TestClient(app)

def test_api_404_json():
    """Verify that unknown API routes return structured VAJRA error JSON."""
    resp = client.get("/api/nonexistent_endpoint_xyz", headers={"Accept": "application/json"})
    assert resp.status_code == 404
    data = resp.json()
    assert data["success"] is False
    assert data["status_code"] == 404
    assert data["code"] == "ERR_E404"
    assert "remediation" in data
    assert "timestamp" in data

def test_browser_404_html():
    """Verify that browser requests to unknown non-API routes return cyber HTML."""
    resp = client.get("/nonexistent_page_abc", headers={"Accept": "text/html,application/xhtml+xml"})
    assert resp.status_code == 404
    assert "text/html" in resp.headers.get("content-type", "")
    assert "VAJRA DEFENSE INTERCEPT" in resp.text
    assert "404" in resp.text

def test_schema_validation_422_json():
    """Verify that invalid schema payloads return structured 422 error JSON with field diagnostics."""
    # /api/chat requires {"prompt": str}
    resp = client.post(
        "/api/chat",
        json={},
        headers={
            "Accept": "application/json",
            "X-Vajra-Signature": VAJRA_SECRET_KEY
        }
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["success"] is False
    assert data["status_code"] == 422
    assert data["code"] == "ERR_E422"
    assert "remediation" in data
    assert "validation_errors" in data

def test_unauthorized_signature_403_json():
    """Verify that invalid signature returns structured 403 error JSON."""
    resp = client.post(
        "/api/chat",
        json={"prompt": "test inquiry"},
        headers={
            "Accept": "application/json",
            "X-Vajra-Signature": "tampered_fake_signature"
        }
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["success"] is False
    assert data["status_code"] == 403
    assert data["code"] == "ERR_E403"
    assert "Forbidden" in data["detail"]
