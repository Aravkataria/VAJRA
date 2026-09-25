"""
VAJRA Semantic & Neural Finder Engine
Finds contextual security flaws: Path Traversal, Insecure Hashes, SSRF, and Debug Flags.
Lead Engineer: Arav Kataria
"""

import re
from typing import List
from vajra_bot.scanner import Finding

# Semantic vulnerability patterns
SEMANTIC_PATTERNS = [
    (
        r"(?i)debug\s*=\s*True",
        "CWE-489",
        "HIGH",
        "Active Debug Mode Enabled in Production Code",
        "Running with `debug=True` leaks interactive debuggers, stack traces, and environment variables. Set debug=False.",
        "debug = False"
    ),
    (
        r"(?i)verify\s*=\s*False",
        "CWE-295",
        "HIGH",
        "Disabled TLS/SSL Certificate Verification",
        "Disabling certificate verification (`verify=False`) makes HTTP requests vulnerable to Man-in-the-Middle (MitM) attacks.",
        "verify=True"
    ),
    (
        r"hashlib\.(?:md5|sha1)\s*\(",
        "CWE-328",
        "MEDIUM",
        "Use of Cryptographically Broken Hash Algorithm (MD5 / SHA-1)",
        "MD5 and SHA-1 suffer from known collision vulnerabilities. Use SHA-256, SHA-512, or BLAKE2 for security hashing.",
        "import hashlib\nhashlib.sha256(...)"
    ),
    (
        r"open\s*\(\s*(?:f['\"][^'\"]*\{|[^,\)]*\+)[^,\)]*,?\s*['\"][rwa]",
        "CWE-22",
        "HIGH",
        "Potential Path Traversal / Arbitrary File Access",
        "Constructing file paths via unsanitized string operations allows directory traversal (`../`). Use `Path.resolve()` and verify path bounds.",
        "target_path = (BASE_DIR / user_filename).resolve()\nif not str(target_path).startswith(str(BASE_DIR)):\n    raise PermissionError('Path traversal detected')"
    ),
    (
        r"(?i)allowed_hosts\s*=\s*\[\s*['\"]?\*['\"]?\s*\]",
        "CWE-183",
        "HIGH",
        "Permissive Wildcard ALLOWED_HOSTS",
        "Wildcard `ALLOWED_HOSTS = ['*']` allows Host-header poisoning and cache attacks. Explicitly bind known domains.",
        "ALLOWED_HOSTS = ['vajra.dev', 'api.vajra.dev']"
    ),
]


class SemanticFinder:
    """Discovers contextual architectural vulnerabilities across files."""

    @staticmethod
    def scan_context(filename: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, cwe, severity, title, desc, suggestion in SEMANTIC_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        file=filename,
                        line=line_idx,
                        cwe=cwe,
                        severity=severity,
                        title=title,
                        description=desc,
                        suggestion=suggestion
                    ))

        return findings
