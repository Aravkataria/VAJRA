# app/analysis/security_ir/extractor.py

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.analysis.cpg_engine import CPGEngine, CodePropertyGraph
from app.analysis.security_ir.schema import (
    BoundaryType,
    SecurityBoundary,
    SecurityConceptType,
    SecurityContext,
    SecurityDataFlow,
    SecurityNode,
    UniversalSecurityIR,
)


class SecurityIRExtractor:
    """
    Multilingual Security Intermediate Representation (Security IR) and Context Extractor.
    Parses multi-language codebases into canonical security concepts and contextual facts.
    """

    SUPPORTED_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".php": "php",
        ".rb": "ruby",
        ".kt": "kotlin",
        ".swift": "swift",
    }

    FRAMEWORK_SIGNATURES = {
        "fastapi": ["FastAPI", "from fastapi import", "APIRouter"],
        "flask": ["Flask(__name__)", "from flask import", "@app.route"],
        "django": ["django.http", "django.db", "django.urls", "models.Model"],
        "express": ["express()", "require('express')", "from 'express'"],
        "spring": ["@RestController", "@GetMapping", "@PostMapping", "org.springframework"],
        "gin": ["gin.Default()", "github.com/gin-gonic/gin"],
        "actix": ["actix_web", "use actix_web::"],
        "aspnet": ["Microsoft.AspNetCore", "[ApiController]", "[HttpGet]"],
        "laravel": ["Route::get", "Route::post", "Illuminate\\Http"],
        "rails": ["class ApplicationController", "ActionController::Base"],
    }

    def __init__(self, cpg_engine: Optional[CPGEngine] = None):
        self.cpg_engine = cpg_engine or CPGEngine()
        self._node_id_seq = 0

    def _next_node_id(self) -> str:
        self._node_id_seq += 1
        return f"sec_node_{self._node_id_seq}"

    def extract_workspace(self, workspace_path: Path) -> SecurityContext:
        """Extract both Universal Security IR and high-level Security Context from a workspace."""
        security_ir = UniversalSecurityIR()
        detected_languages: Set[str] = set()
        detected_frameworks: Set[str] = set()
        http_endpoints: List[Dict[str, Any]] = []
        auth_mechanisms: Set[str] = set()
        database_types: Set[str] = set()
        config_files: List[str] = []
        dependencies: List[str] = []

        workspace_path = Path(workspace_path)
        all_files: List[Tuple[Path, str, str]] = []

        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                full_path = Path(root) / file_name
                rel_path = str(full_path.relative_to(workspace_path)).replace("\\", "/")
                ext = full_path.suffix.lower()

                # Configuration / Dependency indexing
                if file_name in ("package.json", "requirements.txt", "pom.xml", "Cargo.toml", "go.mod", "Gemfile"):
                    config_files.append(rel_path)
                    try:
                        dep_text = full_path.read_text(encoding="utf-8", errors="ignore")
                        dependencies.extend([line.strip() for line in dep_text.splitlines()[:50] if line.strip()])
                    except Exception:
                        pass

                lang = self.SUPPORTED_EXTENSIONS.get(ext)
                if not lang:
                    continue

                detected_languages.add(lang)
                try:
                    content = full_path.read_text(encoding="utf-8", errors="ignore")
                    all_files.append((full_path, rel_path, content))
                except Exception:
                    continue

        # Extract per-file Security IR nodes and detect frameworks
        for full_path, rel_path, content in all_files:
            lang = self.SUPPORTED_EXTENSIONS[full_path.suffix.lower()]
            self._detect_frameworks(content, detected_frameworks)
            self._detect_auth_mechanisms(content, auth_mechanisms)
            self._detect_databases(content, database_types)
            
            file_nodes, file_boundaries = self._extract_file_ir(rel_path, content, lang)
            for node in file_nodes:
                security_ir.add_node(node)
            security_ir.boundaries.extend(file_boundaries)

            # Extract HTTP endpoints
            endpoints = self._extract_endpoints(rel_path, content, lang)
            http_endpoints.extend(endpoints)

        # Cross-file / intra-file data flow inference
        security_ir.flows = self._infer_security_data_flows(security_ir)

        # Determine architecture type
        arch_type = "library"
        if http_endpoints:
            arch_type = "web_service" if len(http_endpoints) < 15 else "monolith_api"
        elif any(n.concept == SecurityConceptType.CLI_INPUT for n in security_ir.nodes.values()):
            arch_type = "cli_tool"

        return SecurityContext(
            repository_name=workspace_path.name,
            detected_languages=sorted(list(detected_languages)),
            detected_frameworks=sorted(list(detected_frameworks)),
            architecture_type=arch_type,
            http_endpoints=http_endpoints,
            auth_mechanisms=sorted(list(auth_mechanisms)),
            database_types=sorted(list(database_types)),
            dependencies=dependencies[:50],
            configuration_files=config_files,
            security_ir=security_ir,
        )

    def _detect_frameworks(self, content: str, detected: Set[str]) -> None:
        for fw, sigs in self.FRAMEWORK_SIGNATURES.items():
            if any(sig in content for sig in sigs):
                detected.add(fw)

    def _detect_auth_mechanisms(self, content: str, detected: Set[str]) -> None:
        lower = content.lower()
        if "jwt" in lower or "jsonwebtoken" in lower or "bearer" in lower:
            detected.add("jwt")
        if "session[" in lower or "express-session" in lower or "session_start" in lower:
            detected.add("session")
        if "oauth" in lower or "oauth2" in lower:
            detected.add("oauth2")
        if "basicauth" in lower or "httpbasic" in lower:
            detected.add("http_basic")

    def _detect_databases(self, content: str, detected: Set[str]) -> None:
        lower = content.lower()
        if "postgres" in lower or "psycopg" in lower or "pg_" in lower:
            detected.add("postgresql")
        if "sqlite" in lower:
            detected.add("sqlite")
        if "mysql" in lower:
            detected.add("mysql")
        if "mongo" in lower or "mongoose" in lower:
            detected.add("mongodb")
        if "redis" in lower:
            detected.add("redis")

    def _extract_file_ir(
        self, rel_path: str, content: str, lang: str
    ) -> Tuple[List[SecurityNode], List[SecurityBoundary]]:
        nodes: List[SecurityNode] = []
        boundaries: List[SecurityBoundary] = []

        lines = content.splitlines()

        # Ingress / Sources patterns across languages
        ingress_patterns = [
            (r"(request\.(args|form|json|GET|POST|values|files))", SecurityConceptType.UNTRUSTED_INPUT),
            (r"(req\.(query|body|params|headers))", SecurityConceptType.UNTRUSTED_INPUT),
            (r"(r\.FormValue|r\.URL\.Query|r\.Body)", SecurityConceptType.UNTRUSTED_INPUT),
            (r"(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)", SecurityConceptType.UNTRUSTED_INPUT),
            (r"(params\[|request\.parameters)", SecurityConceptType.UNTRUSTED_INPUT),
            (r"(@RequestParam|@PathVariable|@RequestBody)", SecurityConceptType.UNTRUSTED_INPUT),
            (r"(sys\.argv|process\.argv|os\.Args|std::env::args)", SecurityConceptType.CLI_INPUT),
            (r"(os\.getenv|os\.environ|process\.env|std::env::var)", SecurityConceptType.ENV_VARIABLE),
        ]

        # Sensitive Sinks patterns
        sink_patterns = [
            (r"(\bexecute\b|\bexecutemany\b|\braw_query\b|\.query\()", SecurityConceptType.RAW_QUERY_SINK),
            (r"(subprocess\.(run|Popen|call)|os\.(system|popen)|child_process\.(exec|spawn)|exec\.Command)", SecurityConceptType.COMMAND_OPERATION),
            (r"(\beval\(|\bexec\(|Function\(|vm\.runInContext)", SecurityConceptType.EVAL_OPERATION),
            (r"(pickle\.loads|yaml\.load\b|marshal\.loads|unserialize\()", SecurityConceptType.DESERIALIZATION_OPERATION),
            (r"(open\(|fs\.readFile|fs\.writeFile|os\.remove|os\.unlink|File\.read)", SecurityConceptType.FS_OPERATION),
            (r"(requests\.(get|post)|fetch\(|http\.Get|axios\.(get|post))", SecurityConceptType.NETWORK_OPERATION),
            (r"(res\.send\(|res\.render\(|render_template_string\(|\.innerHTML\s*=)", SecurityConceptType.RESPONSE_RENDER_SINK),
        ]

        # Controls & Boundary patterns
        control_patterns = [
            (r"(is_authenticated|current_user|req\.user|session\.get\(['\"]user)", SecurityConceptType.AUTHN_BOUNDARY),
            (r"(has_permission|has_role|is_admin|check_permission|user_id\s*==\s*owner_id|assert_owner)", SecurityConceptType.AUTHZ_BOUNDARY),
            (r"(rate_limit|limiter\.limit|throttle|RateLimiter)", SecurityConceptType.RATE_LIMIT_CONTROL),
            (r"(int\(|float\(|validator\.|escape\(|DOMPurify|sanitize)", SecurityConceptType.SANITIZATION),
        ]

        for idx, line in enumerate(lines, start=1):
            trimmed = line.strip()
            if not trimmed or trimmed.startswith(("#", "//", "/*", "*")):
                continue

            # Check Ingress
            for pat, concept in ingress_patterns:
                if re.search(pat, trimmed):
                    nodes.append(
                        SecurityNode(
                            node_id=self._next_node_id(),
                            concept=concept,
                            language=lang,
                            file_path=rel_path,
                            start_line=idx,
                            end_line=idx,
                            raw_code=trimmed[:120],
                            symbol_name="ingress",
                        )
                    )

            # Check Sinks
            for pat, concept in sink_patterns:
                if re.search(pat, trimmed):
                    nodes.append(
                        SecurityNode(
                            node_id=self._next_node_id(),
                            concept=concept,
                            language=lang,
                            file_path=rel_path,
                            start_line=idx,
                            end_line=idx,
                            raw_code=trimmed[:120],
                            symbol_name="sink",
                        )
                    )

            # Check Controls
            for pat, concept in control_patterns:
                if re.search(pat, trimmed):
                    nodes.append(
                        SecurityNode(
                            node_id=self._next_node_id(),
                            concept=concept,
                            language=lang,
                            file_path=rel_path,
                            start_line=idx,
                            end_line=idx,
                            raw_code=trimmed[:120],
                            symbol_name="control",
                        )
                    )
                    b_type = (
                        BoundaryType.AUTHENTICATION
                        if "auth" in trimmed.lower()
                        else BoundaryType.AUTHORIZATION
                    )
                    boundaries.append(
                        SecurityBoundary(
                            boundary_id=f"b_{len(boundaries)+1}",
                            boundary_type=b_type,
                            file_path=rel_path,
                            line_number=idx,
                            enclosing_function="function",
                            guard_expression=trimmed[:80],
                        )
                    )

        return nodes, boundaries

    def _extract_endpoints(self, rel_path: str, content: str, lang: str) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []
        lines = content.splitlines()

        route_patterns = [
            r"@(?:app|router|api)\.(get|post|put|delete|patch)\([\"']([^\"']+)[\"']",
            r"(?:app|router)\.(get|post|put|delete|patch)\([\"']([^\"']+)[\"']",
            r"@app\.route\([\"']([^\"']+)[\"'](?:,\s*methods=\[['\"]([A-Z]+)['\"][\]\)])?",
            r"Route::(get|post|put|delete)\([\"']([^\"']+)[\"']",
            r"@(?:GetMapping|PostMapping|RequestMapping)\([\"']?([^\"'\)]+)[\"']?\)",
        ]

        for idx, line in enumerate(lines, start=1):
            for pat in route_patterns:
                match = re.search(pat, line)
                if match:
                    groups = match.groups()
                    if len(groups) == 2:
                        first = groups[0] or "ANY"
                        second = groups[1] or ""
                        # If route was first and method was second (like @app.route)
                        if first.startswith("/") and second:
                            endpoints.append({
                                "method": second.upper(),
                                "path": first,
                                "file": rel_path,
                                "line": idx,
                            })
                        elif first.startswith("/"):
                            endpoints.append({
                                "method": "ANY",
                                "path": first,
                                "file": rel_path,
                                "line": idx,
                            })
                        else:
                            endpoints.append({
                                "method": first.upper(),
                                "path": second,
                                "file": rel_path,
                                "line": idx,
                            })
                    elif len(groups) == 1:
                        endpoints.append({
                            "method": "ANY",
                            "path": groups[0],
                            "file": rel_path,
                            "line": idx,
                        })

        return endpoints

    def _infer_security_data_flows(self, ir: UniversalSecurityIR) -> List[SecurityDataFlow]:
        flows: List[SecurityDataFlow] = []
        sources = [n for n in ir.nodes.values() if n.concept in (
            SecurityConceptType.UNTRUSTED_INPUT,
            SecurityConceptType.CLI_INPUT,
            SecurityConceptType.ENV_VARIABLE,
        )]
        sinks = [n for n in ir.nodes.values() if n.concept in (
            SecurityConceptType.RAW_QUERY_SINK,
            SecurityConceptType.COMMAND_OPERATION,
            SecurityConceptType.EVAL_OPERATION,
            SecurityConceptType.DESERIALIZATION_OPERATION,
            SecurityConceptType.FS_OPERATION,
            SecurityConceptType.RESPONSE_RENDER_SINK,
        )]

        flow_idx = 0
        for src in sources:
            for sink in sinks:
                # Same file flow
                if src.file_path == sink.file_path and sink.start_line >= src.start_line:
                    flow_idx += 1
                    flows.append(
                        SecurityDataFlow(
                            flow_id=f"flow_{flow_idx}",
                            source_node_id=src.node_id,
                            sink_node_id=sink.node_id,
                            is_cross_file=False,
                            is_cross_function=src.enclosing_function != sink.enclosing_function,
                        )
                    )
                # Cross file flow heuristic
                elif src.file_path != sink.file_path:
                    flow_idx += 1
                    flows.append(
                        SecurityDataFlow(
                            flow_id=f"flow_{flow_idx}",
                            source_node_id=src.node_id,
                            sink_node_id=sink.node_id,
                            is_cross_file=True,
                            is_cross_function=True,
                        )
                    )

        return flows
