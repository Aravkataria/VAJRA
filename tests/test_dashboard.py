# tests/test_dashboard.py

from app.dashboard.renderer import render_dashboard_html


def test_render_dashboard_html_structure():
    reports = [{
        "workspace_id": "ws-123",
        "generated_at": "2026-08-29T12:00:00Z",
        "summary": {
            "initial_findings": 2,
            "final_findings": 0,
            "verified_repairs": 2,
            "structured_non_repairs": 0,
        }
    }]
    declined = []
    html = render_dashboard_html(reports, declined)
    assert "VAJRA" in html
    assert "ws-123" in html
    assert "2 verified" in html