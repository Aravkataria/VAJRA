# tests/test_independent_analyst.py

import pytest
from app.analysis.finding import DiscoveryPath, ReviewStatus, UnifiedFinding, FindingLocation
from app.analysis.independent_analyst import IndependentAIAnalyst
from app.analysis.security_ir.schema import (
    SecurityConceptType,
    SecurityContext,
    SecurityNode,
    UniversalSecurityIR,
)


def test_unified_finding_serialization():
    loc = FindingLocation(start_line=12, end_line=14, function="get_user")
    f = UnifiedFinding(
        finding_id="FIND-999",
        category="broken_object_level_authorization",
        cwe="CWE-639",
        severity="HIGH",
        confidence=0.94,
        file="controllers/user.ts",
        location=loc,
        source="req.params.id",
        sink="db.getUser",
        evidence=["No ownership check"],
        reasoning="IDOR vulnerability",
        impact="Data leakage",
        repair_required=True,
        review_status=ReviewStatus.CONFIRMED,
        discovery_path=DiscoveryPath.AI_ONLY,
    )

    d = f.to_dict()
    assert d["finding_id"] == "FIND-999"
    assert d["cwe"] == "CWE-639"
    assert d["location"]["start_line"] == 12
    assert d["discovery_path"] == "ai_only"
    assert d["review_status"] == "confirmed"


def test_independent_discovery_heuristics():
    ir = UniversalSecurityIR()
    ir.add_node(
        SecurityNode(
            node_id="n1",
            concept=SecurityConceptType.UNTRUSTED_INPUT,
            language="python",
            file_path="app/auth.py",
            start_line=5,
            end_line=5,
            raw_code="username = request.form['username']",
        )
    )

    context = SecurityContext(
        repository_name="test_repo",
        detected_languages=["python"],
        detected_frameworks=["fastapi"],
        architecture_type="web_service",
        http_endpoints=[
            {"method": "POST", "path": "/api/login", "file": "app/auth.py", "line": 4},
            {"method": "GET", "path": "/user/{id}", "file": "app/routes.py", "line": 10},
        ],
        auth_mechanisms=["jwt"],
        security_ir=ir,
        deterministic_rule_findings=[{
            "vulnerability_type": "sql_injection",
            "file": "app/db.py",
            "line": 45,
            "call_name": "execute",
            "severity": "CRITICAL",
        }],
    )

    analyst = IndependentAIAnalyst()
    findings = analyst.analyze_workspace(context)

    assert len(findings) >= 2
    # Check that rule finding was validated
    assert any(f.discovery_path == DiscoveryPath.DUAL_CONFIRMED for f in findings)
    # Check that missing rate limiting was independently discovered
    assert any(f.category == "missing_rate_limiting" and f.discovery_path == DiscoveryPath.AI_ONLY for f in findings)
    # Check that IDOR was independently discovered
    assert any(f.category == "broken_object_level_authorization" and f.discovery_path == DiscoveryPath.AI_ONLY for f in findings)
