# app/analysis/security_ir/taxonomy.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class VulnerabilityTaxonomyEntry:
    category_id: str
    name: str
    cwe_id: str
    default_severity: str
    description: str
    requires_repair: bool = True


# Broad-spectrum vulnerability taxonomy covering 25+ categories across web, system, API, and cloud
TAXONOMY_REGISTRY: Dict[str, VulnerabilityTaxonomyEntry] = {
    # 1. Access Control & Authorization
    "broken_object_level_authorization": VulnerabilityTaxonomyEntry(
        category_id="broken_object_level_authorization",
        name="Broken Object Level Authorization (IDOR)",
        cwe_id="CWE-639",
        default_severity="HIGH",
        description="Endpoint exposes sensitive user objects based on user-supplied identifier without verifying requester ownership.",
    ),
    "broken_function_level_authorization": VulnerabilityTaxonomyEntry(
        category_id="broken_function_level_authorization",
        name="Broken Function Level Authorization (Privilege Escalation)",
        cwe_id="CWE-285",
        default_severity="HIGH",
        description="Administrative or privileged actions can be invoked by unprivileged roles due to missing role/permission checks.",
    ),
    "authentication_bypass": VulnerabilityTaxonomyEntry(
        category_id="authentication_bypass",
        name="Authentication Bypass",
        cwe_id="CWE-287",
        default_severity="CRITICAL",
        description="Flaw in authentication logic allows requests to bypass identity verification entirely.",
    ),
    "session_fixation_hijack": VulnerabilityTaxonomyEntry(
        category_id="session_fixation_hijack",
        name="Insecure Session or Token Management",
        cwe_id="CWE-384",
        default_severity="HIGH",
        description="Session tokens are predictable, persistent across privilege levels, or missing signature verification.",
    ),

    # 2. Injection Vulnerabilities
    "sql_injection": VulnerabilityTaxonomyEntry(
        category_id="sql_injection",
        name="SQL Injection",
        cwe_id="CWE-89",
        default_severity="CRITICAL",
        description="Untrusted user input concatenated directly into raw database query strings.",
    ),
    "nosql_injection": VulnerabilityTaxonomyEntry(
        category_id="nosql_injection",
        name="NoSQL Injection",
        cwe_id="CWE-943",
        default_severity="HIGH",
        description="Untrusted query operators or objects injected directly into NoSQL filter criteria.",
    ),
    "command_injection": VulnerabilityTaxonomyEntry(
        category_id="command_injection",
        name="OS Command Injection",
        cwe_id="CWE-78",
        default_severity="CRITICAL",
        description="Untrusted input passed directly to operating system shell or process executor.",
    ),
    "ldap_injection": VulnerabilityTaxonomyEntry(
        category_id="ldap_injection",
        name="LDAP Injection",
        cwe_id="CWE-90",
        default_severity="HIGH",
        description="Unsanitized input embedded within LDAP search filters.",
    ),
    "server_side_template_injection": VulnerabilityTaxonomyEntry(
        category_id="server_side_template_injection",
        name="Server-Side Template Injection (SSTI)",
        cwe_id="CWE-1336",
        default_severity="CRITICAL",
        description="User input rendered directly into server-side template engine context allowing arbitrary evaluation.",
    ),
    "cross_site_scripting": VulnerabilityTaxonomyEntry(
        category_id="cross_site_scripting",
        name="Cross-Site Scripting (XSS)",
        cwe_id="CWE-79",
        default_severity="MEDIUM",
        description="Untrusted data reflected or stored in web responses without contextual encoding.",
    ),

    # 3. Server-Side & File Insecurities
    "server_side_request_forgery": VulnerabilityTaxonomyEntry(
        category_id="server_side_request_forgery",
        name="Server-Side Request Forgery (SSRF)",
        cwe_id="CWE-918",
        default_severity="HIGH",
        description="Server fetches remote resources using untrusted, user-supplied URI without egress network restrictions.",
    ),
    "path_traversal": VulnerabilityTaxonomyEntry(
        category_id="path_traversal",
        name="Path Traversal & Arbitrary File Access",
        cwe_id="CWE-22",
        default_severity="HIGH",
        description="User-supplied paths containing directory traversal tokens (../) reach file reading/writing sinks.",
    ),
    "unsafe_deserialization": VulnerabilityTaxonomyEntry(
        category_id="unsafe_deserialization",
        name="Unsafe Object Deserialization",
        cwe_id="CWE-502",
        default_severity="CRITICAL",
        description="Untrusted byte streams passed to native object deserializers (pickle, yaml.load, Java ObjectInputStream).",
    ),

    # 4. Cryptographic, Secrets & Data Leakage
    "hardcoded_credentials": VulnerabilityTaxonomyEntry(
        category_id="hardcoded_credentials",
        name="Hardcoded Secret or Credential Exposure",
        cwe_id="CWE-798",
        default_severity="HIGH",
        description="API keys, cryptographic secrets, or database passwords hardcoded directly in source code.",
    ),
    "weak_cryptography": VulnerabilityTaxonomyEntry(
        category_id="weak_cryptography",
        name="Weak Cryptographic Primitive or Mode",
        cwe_id="CWE-327",
        default_severity="MEDIUM",
        description="Use of broken algorithms (MD5, SHA1, DES, ECB mode) or insufficient key lengths for security purposes.",
    ),
    "information_disclosure": VulnerabilityTaxonomyEntry(
        category_id="information_disclosure",
        name="Sensitive Information / Stack Trace Disclosure",
        cwe_id="CWE-209",
        default_severity="LOW",
        description="Raw internal exceptions, database schema details, or environment diagnostics exposed to clients.",
    ),

    # 5. Resource Consumption & Abuse
    "missing_rate_limiting": VulnerabilityTaxonomyEntry(
        category_id="missing_rate_limiting",
        name="Missing Rate Limiting / Abuse Control",
        cwe_id="CWE-770",
        default_severity="MEDIUM",
        description="Sensitive authentication or computational endpoint lacks throttling, enabling brute-force or resource exhaustion.",
    ),
    "algorithmic_complexity_abuse": VulnerabilityTaxonomyEntry(
        category_id="algorithmic_complexity_abuse",
        name="Algorithmic Complexity / ReDoS / Unbounded Memory",
        cwe_id="CWE-1333",
        default_severity="MEDIUM",
        description="Catastrophic backtracking regular expression or unbounded memory allocation driven by user input length.",
    ),

    # 6. Concurrency & Logic
    "race_condition_toctou": VulnerabilityTaxonomyEntry(
        category_id="race_condition_toctou",
        name="Race Condition / Time-of-Check to Time-of-Use (TOCTOU)",
        cwe_id="CWE-367",
        default_severity="HIGH",
        description="State check occurs separately from state modification, allowing concurrent execution to bypass validation.",
    ),
    "business_logic_bypass": VulnerabilityTaxonomyEntry(
        category_id="business_logic_bypass",
        name="Business Logic Flow Bypass",
        cwe_id="CWE-840",
        default_severity="HIGH",
        description="Multi-step transactional flow fails to enforce sequential validation or payment/verification state invariant.",
    ),

    # 7. Low-Level, Memory & Supply Chain
    "memory_safety_buffer_overflow": VulnerabilityTaxonomyEntry(
        category_id="memory_safety_buffer_overflow",
        name="Memory Safety / Buffer Overflow / Out-of-Bounds Access",
        cwe_id="CWE-119",
        default_severity="CRITICAL",
        description="Unbounded string/buffer copy in native languages (C/C++/Rust unsafe) allowing arbitrary memory corruption.",
    ),
    "insecure_dependency_supply_chain": VulnerabilityTaxonomyEntry(
        category_id="insecure_dependency_supply_chain",
        name="Insecure Dependency or Known Vulnerable Component",
        cwe_id="CWE-1395",
        default_severity="HIGH",
        description="Project imports library versions with known critical public advisories.",
    ),
    "insecure_configuration": VulnerabilityTaxonomyEntry(
        category_id="insecure_configuration",
        name="Insecure Framework or Server Configuration",
        cwe_id="CWE-16",
        default_severity="MEDIUM",
        description="Debug mode enabled in production, wildcard CORS headers, or disabled security headers (HSTS, CSP).",
    ),
}


def lookup_taxonomy(category_id: str) -> Optional[VulnerabilityTaxonomyEntry]:
    """Retrieve taxonomy metadata by category id (case-insensitive & alias-aware)."""
    norm = category_id.lower().strip().replace("-", "_").replace(" ", "_")
    if norm in TAXONOMY_REGISTRY:
        return TAXONOMY_REGISTRY[norm]
    
    # Common alias matching
    aliases = {
        "idor": "broken_object_level_authorization",
        "sqli": "sql_injection",
        "cmdi": "command_injection",
        "xss": "cross_site_scripting",
        "ssrf": "server_side_request_forgery",
        "rce": "command_injection",
        "hardcoded_secret": "hardcoded_credentials",
        "rate_limiting": "missing_rate_limiting",
        "toctou": "race_condition_toctou",
    }
    alias_match = aliases.get(norm)
    if alias_match and alias_match in TAXONOMY_REGISTRY:
        return TAXONOMY_REGISTRY[alias_match]
    return None
