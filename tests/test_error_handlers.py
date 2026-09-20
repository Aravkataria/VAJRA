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
    """Verify that invalid schema payloads return structured 422 error JSON with field diagnostics for public callers."""
    # /api/chat requires {"prompt": str}
    resp = client.post(
        "/api/chat",
        json={},
        headers={"Accept": "application/json"}
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["success"] is False
    assert data["status_code"] == 422
    assert data["code"] == "ERR_E422"
    assert "remediation" in data
    assert "validation_errors" in data

def test_unauthorized_signature_403_json():
    """Verify that invalid or tampered signature returns structured 403 error JSON."""
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

def test_valid_signature_authenticated(monkeypatch):
    """Verify that a valid server-to-server signature is accepted."""
    test_secret = "test_server_secret_998877"
    monkeypatch.setenv("VAJRA_SECRET_KEY", test_secret)
    # Testing schema validation with authenticated signature
    resp = client.post(
        "/api/chat",
        json={},
        headers={
            "Accept": "application/json",
            "X-Vajra-Signature": test_secret
        }
    )
    # Passes authentication check and reaches schema validation
    assert resp.status_code == 422

def test_chat_rate_limiting_429():
    """Verify that unauthenticated public callers exceeding chat rate limits receive HTTP 429."""
    from app.api import _ip_chat_history, MAX_CHAT_PER_WINDOW
    import time
    # Seed history to simulate hitting the rate limit
    _ip_chat_history["testclient"] = [time.time()] * MAX_CHAT_PER_WINDOW
    try:
        resp = client.post(
            "/api/chat",
            json={"prompt": "hello"},
            headers={"Accept": "application/json"}
        )
        assert resp.status_code == 429
        data = resp.json()
        assert data["success"] is False
        assert data["rate_limited"] is True
        assert data["code"] == "CHAT_RATE_LIMIT"
        assert "Retry-After" in resp.headers
    finally:
        _ip_chat_history.pop("testclient", None)

