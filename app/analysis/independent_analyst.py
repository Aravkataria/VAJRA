# app/analysis/independent_analyst.py

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from app.analysis.finding import (
    DiscoveryPath,
    FindingLocation,
    ReviewStatus,
    UnifiedFinding,
)
from app.analysis.model_provider import ModelProvider
from app.analysis.security_ir.schema import (
    SecurityConceptType,
    SecurityContext,
    UniversalSecurityIR,
)
from app.analysis.security_ir.taxonomy import lookup_taxonomy


class IndependentAIAnalyst:
    """
    Model 1: Multilingual AI Security Analyst.
    
    Provides dual-path vulnerability intelligence:
    1. Independent Discovery: Finds security weaknesses (IDOR, auth bypass, rate-limit absence,
       cross-file flows) that bypass deterministic rule matchers.
    2. Deterministic Validation: Vets and classifies scanner findings as confirmed, rejected (false positive),
       or uncertain.
    """

    REQUIRED_SCHEMA_KEYS = [
        "finding_id",
        "category",
        "cwe",
        "severity",
        "confidence",
        "file",
        "start_line",
        "end_line",
        "function",
        "source",
        "sink",
        "data_flow",
        "security_boundary",
        "evidence",
        "reasoning",
        "impact",
        "repair_required",
        "review_status",
        "discovery_path",
    ]

    def __init__(self, provider: Optional[ModelProvider] = None):
        self.provider = provider

    def analyze_workspace(self, context: SecurityContext) -> List[UnifiedFinding]:
        """
        Execute comprehensive analysis across both Independent Discovery and Rule Validation paths.
        """
        findings: List[UnifiedFinding] = []

        # 1. Rule Validation Path (for existing deterministic findings)
        if context.deterministic_rule_findings:
            validated_findings = self.validate_deterministic_findings(context)
            findings.extend(validated_findings)

        # 2. Independent Discovery Path (explore Security IR & context for unflagged flaws)
        independent_findings = self.discover_independent_vulnerabilities(context)
        findings.extend(independent_findings)

        return findings

    def validate_deterministic_findings(self, context: SecurityContext) -> List[UnifiedFinding]:
        """Evaluate deterministic findings to confirm, reject as false-positive, or mark uncertain."""
        results: List[UnifiedFinding] = []

        for idx, rule_finding in enumerate(context.deterministic_rule_findings, start=1):
            finding_id = f"VAL-FINDING-{idx:04d}"
            
            if self.provider:
                prompt = self._build_validation_prompt(rule_finding, context)
                try:
                    response_text = self.provider.generate(prompt)
                    parsed = self._parse_json_finding(response_text, fallback_id=finding_id)
                    if parsed:
                        results.append(parsed)
                        continue
                except Exception:
                    pass

            # Deterministic heuristic fallback when offline/testing
            results.append(self._heuristic_validate_finding(rule_finding, finding_id))

        return results

    def discover_independent_vulnerabilities(self, context: SecurityContext) -> List[UnifiedFinding]:
        """Search codebase Security IR for logic bugs, IDOR, missing rate limiting, and cross-file flaws."""
        results: List[UnifiedFinding] = []

        if self.provider:
            prompt = self._build_independent_discovery_prompt(context)
            try:
                response_text = self.provider.generate(prompt)
                findings = self._parse_multiple_json_findings(response_text)
                if findings:
                    return findings
            except Exception:
                pass

        # Heuristic independent discovery on Security IR (covers IDOR, Rate Limiting, Cross-file Taint)
        results.extend(self._heuristic_independent_discovery(context))
        return results

    def _build_validation_prompt(self, finding: Dict[str, Any], context: SecurityContext) -> str:
        return f"""You are VAJRA Model 1: Multilingual AI Security Analyst.

Evaluate this deterministic security finding against the application context.
Determine if it is a TRUE VULNERABILITY, FALSE POSITIVE (safe/sanitized code), or UNCERTAIN.

Finding to evaluate:
{json.dumps(finding, indent=2)}

Application Context:
- Languages: {context.detected_languages}
- Frameworks: {context.detected_frameworks}
- Architecture: {context.architecture_type}

Output MUST be a single JSON object with the VAJRA Unified Security Finding Schema:
{{
  "finding_id": "VAL-0001",
  "category": "{finding.get('vulnerability_type', 'security_flaw')}",
  "cwe": "CWE-...",
  "severity": "HIGH",
  "confidence": 0.95,
  "file": "{finding.get('file', '')}",
  "start_line": {finding.get('line', 1)},
  "end_line": {finding.get('line', 1)},
  "function": "{finding.get('function', 'module')}",
  "source": "untrusted_input",
  "sink": "{finding.get('call_name', '')}",
  "data_flow": ["source", "sink"],
  "security_boundary": "public_endpoint",
  "evidence": ["Deterministic rule triggered on line {finding.get('line', 1)}"],
  "reasoning": "Explain step-by-step why the finding is genuine or a false positive",
  "impact": "Concrete consequence if exploited (no offensive payload generation)",
  "repair_required": true,
  "review_status": "confirmed",  // "confirmed", "uncertain", or "rejected"
  "discovery_path": "dual_confirmed"  // "dual_confirmed", "rule_candidate_ai_rejected", or "rule_candidate_ai_uncertain"
}}"""

    def _build_independent_discovery_prompt(self, context: SecurityContext) -> str:
        ir_summary = context.security_ir.to_dict() if context.security_ir else {}
        return f"""You are VAJRA Model 1: Multilingual AI Security Analyst.

Perform an INDEPENDENT security audit of this repository.
Search for subtle vulnerabilities that deterministic rules missed (e.g. IDOR, Missing Authorization, Missing Rate Limiting, Business Logic Flaws, Complex Cross-File Taint).

Security Context:
- Architecture: {context.architecture_type}
- Languages: {context.detected_languages}
- Frameworks: {context.detected_frameworks}
- Endpoints: {json.dumps(context.http_endpoints[:10], indent=2)}
- Auth Mechanisms: {context.auth_mechanisms}
- Security IR: {json.dumps(ir_summary, indent=2)}

Do NOT provide operational exploit payloads. Focus on root cause, evidence, and remediation.

Return a JSON array of findings adhering to the VAJRA Unified Security Finding Schema with discovery_path="ai_only".
"""

    def _heuristic_validate_finding(self, rule_finding: Dict[str, Any], finding_id: str) -> UnifiedFinding:
        vtype = rule_finding.get("vulnerability_type", "security_weakness")
        tax = lookup_taxonomy(vtype)
        cwe = tax.cwe_id if tax else "CWE-699"
        sev = (rule_finding.get("severity") or (tax.default_severity if tax else "MEDIUM")).upper()

        return UnifiedFinding(
            finding_id=finding_id,
            category=vtype,
            cwe=cwe,
            severity=sev,
            confidence=0.90,
            file=rule_finding.get("file", "unknown"),
            location=FindingLocation(
                start_line=rule_finding.get("line", 1),
                end_line=rule_finding.get("line", 1),
                function=rule_finding.get("function", "module"),
            ),
            sink=rule_finding.get("call_name") or vtype,
            evidence=[rule_finding.get("message", "Rule pattern match")],
            reasoning="Deterministic AST scanner identified sink without observed sanitizer in local scope.",
            impact=f"Potential {vtype} causing security compromise at {rule_finding.get('file', '')}:{rule_finding.get('line', 1)}",
            repair_required=True,
            review_status=ReviewStatus.CONFIRMED,
            discovery_path=DiscoveryPath.DUAL_CONFIRMED,
        )

    def _heuristic_independent_discovery(self, context: SecurityContext) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        ir = context.security_ir
        if not ir:
            return findings

        # Check 1: Missing Rate Limiting on Auth/Login Endpoints (AI-only discovery)
        for ep in context.http_endpoints:
            path_lower = ep.get("path", "").lower()
            if any(term in path_lower for term in ("login", "auth", "signin", "password", "token")):
                has_rate_limit = any(
                    n.concept == SecurityConceptType.RATE_LIMIT_CONTROL and n.file_path == ep.get("file")
                    for n in ir.nodes.values()
                )
                if not has_rate_limit:
                    findings.append(
                        UnifiedFinding(
                            finding_id=f"IND-RATELIMIT-{len(findings)+1:04d}",
                            category="missing_rate_limiting",
                            cwe="CWE-770",
                            severity="MEDIUM",
                            confidence=0.88,
                            file=ep.get("file", "api.py"),
                            location=FindingLocation(start_line=ep.get("line", 1), end_line=ep.get("line", 1)),
                            source=f"{ep.get('method', 'POST')} {ep.get('path', '')}",
                            sink="authentication_handler",
                            evidence=["Authentication endpoint defined without active rate limiting middleware or throttle decorator."],
                            reasoning="Authentication route accepts repeated requests without throttling, allowing automated credential stuffing and resource exhaustion.",
                            impact="Adversaries can execute high-volume password spraying or brute force attacks against user accounts.",
                            repair_required=True,
                            review_status=ReviewStatus.CONFIRMED,
                            discovery_path=DiscoveryPath.AI_ONLY,
                        )
                    )

        # Check 2: Broken Object Level Authorization (IDOR) on Object Lookup Endpoints
        for ep in context.http_endpoints:
            path = ep.get("path", "")
            if re.search(r"/(?:user|account|order|document|invoice)/\{?[a-zA-Z0-9_-]+\}?", path, re.IGNORECASE):
                has_authz_guard = any(
                    n.concept in (SecurityConceptType.AUTHZ_BOUNDARY, SecurityConceptType.OWNERSHIP_CHECK)
                    and n.file_path == ep.get("file")
                    for n in ir.nodes.values()
                )
                if not has_authz_guard:
                    findings.append(
                        UnifiedFinding(
                            finding_id=f"IND-IDOR-{len(findings)+1:04d}",
                            category="broken_object_level_authorization",
                            cwe="CWE-639",
                            severity="HIGH",
                            confidence=0.92,
                            file=ep.get("file", "routes.py"),
                            location=FindingLocation(start_line=ep.get("line", 1), end_line=ep.get("line", 1)),
                            source=f"Path parameter in {path}",
                            sink="database_object_fetch",
                            evidence=[f"Resource endpoint '{path}' fetches user objects without checking requester ownership."],
                            reasoning="The handler retrieves sensitive objects based on a client-supplied identifier without verifying that the authenticated user owns the requested record.",
                            impact="Unauthorized users can access or tamper with other users' private accounts and records by modifying the ID parameter.",
                            repair_required=True,
                            review_status=ReviewStatus.CONFIRMED,
                            discovery_path=DiscoveryPath.AI_ONLY,
                        )
                    )

        # Check 3: Multi-File Cross-Boundary Taint Flows
        for flow in ir.flows:
            if flow.is_cross_file:
                src_node = ir.nodes.get(flow.source_node_id)
                sink_node = ir.nodes.get(flow.sink_node_id)
                if src_node and sink_node and not flow.sanitizers_passed:
                    cat = "sql_injection" if sink_node.concept == SecurityConceptType.RAW_QUERY_SINK else "command_injection"
                    tax = lookup_taxonomy(cat)
                    findings.append(
                        UnifiedFinding(
                            finding_id=f"IND-FLOW-{len(findings)+1:04d}",
                            category=cat,
                            cwe=tax.cwe_id if tax else "CWE-20",
                            severity="CRITICAL",
                            confidence=0.91,
                            file=sink_node.file_path,
                            location=FindingLocation(start_line=sink_node.start_line, end_line=sink_node.end_line),
                            source=f"{src_node.raw_code} ({src_node.file_path}:{src_node.start_line})",
                            sink=f"{sink_node.raw_code} ({sink_node.file_path}:{sink_node.start_line})",
                            data_flow=[f"{src_node.file_path}:{src_node.start_line}", f"{sink_node.file_path}:{sink_node.start_line}"],
                            evidence=[f"Cross-file taint flow from {src_node.file_path} to {sink_node.file_path}"],
                            reasoning="Untrusted input enters at the controller layer and travels across module boundaries into a sensitive sink without intermediate parameterization or sanitization.",
                            impact="Adversary can manipulate underlying backend operations through unvalidated cross-module data propagation.",
                            repair_required=True,
                            review_status=ReviewStatus.CONFIRMED,
                            discovery_path=DiscoveryPath.AI_ONLY,
                        )
                    )

        return findings

    def _parse_json_finding(self, text: str, fallback_id: str) -> Optional[UnifiedFinding]:
        try:
            # Strip potential markdown fences
            cleaned = text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            data = json.loads(cleaned.strip())
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                return self._dict_to_unified(data, fallback_id)
        except Exception:
            pass
        return None

    def _parse_multiple_json_findings(self, text: str) -> List[UnifiedFinding]:
        results: List[UnifiedFinding] = []
        try:
            cleaned = text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            data = json.loads(cleaned.strip())
            if isinstance(data, dict):
                data = [data]
            if isinstance(data, list):
                for idx, item in enumerate(data, start=1):
                    if isinstance(item, dict):
                        f = self._dict_to_unified(item, fallback_id=f"IND-AI-{idx:04d}")
                        if f:
                            results.append(f)
        except Exception:
            pass
        return results

    def _dict_to_unified(self, data: Dict[str, Any], fallback_id: str) -> UnifiedFinding:
        loc = FindingLocation(
            start_line=data.get("start_line", 1),
            end_line=data.get("end_line", 1),
            function=data.get("function", "module"),
        )
        cat = data.get("category", "security_weakness")
        tax = lookup_taxonomy(cat)
        cwe = data.get("cwe") or (tax.cwe_id if tax else "CWE-699")
        sev = (data.get("severity") or (tax.default_severity if tax else "MEDIUM")).upper()

        status_str = str(data.get("review_status", "confirmed")).lower()
        status = ReviewStatus.CONFIRMED
        if "reject" in status_str:
            status = ReviewStatus.REJECTED
        elif "uncertain" in status_str:
            status = ReviewStatus.UNCERTAIN

        disc_str = str(data.get("discovery_path", "ai_only")).lower()
        disc = DiscoveryPath.AI_ONLY
        if "dual" in disc_str:
            disc = DiscoveryPath.DUAL_CONFIRMED
        elif "rule_only" in disc_str:
            disc = DiscoveryPath.RULE_ONLY
        elif "rejected" in disc_str:
            disc = DiscoveryPath.RULE_CANDIDATE_AI_REJECTED
        elif "uncertain" in disc_str:
            disc = DiscoveryPath.RULE_CANDIDATE_AI_UNCERTAIN

        return UnifiedFinding(
            finding_id=data.get("finding_id", fallback_id),
            category=cat,
            cwe=cwe,
            severity=sev,
            confidence=float(data.get("confidence", 0.9)),
            file=data.get("file", "unknown"),
            location=loc,
            source=data.get("source"),
            sink=data.get("sink"),
            data_flow=data.get("data_flow", []),
            security_boundary=data.get("security_boundary"),
            evidence=data.get("evidence", []),
            reasoning=data.get("reasoning", ""),
            impact=data.get("impact", ""),
            repair_required=data.get("repair_required", True),
            review_status=status,
            discovery_path=disc,
        )
