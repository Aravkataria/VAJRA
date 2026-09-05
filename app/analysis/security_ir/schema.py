# app/analysis/security_ir/schema.py

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class SecurityConceptType(str, Enum):
    # Ingress / Sources
    UNTRUSTED_INPUT = "untrusted_input"
    TRUSTED_INPUT = "trusted_input"
    HTTP_ENDPOINT = "http_endpoint"
    RPC_ENDPOINT = "rpc_endpoint"
    CLI_INPUT = "cli_input"
    ENV_VARIABLE = "env_variable"
    FILE_INPUT = "file_input"
    DATABASE_INPUT = "database_input"
    MESSAGE_QUEUE_INPUT = "message_queue_input"

    # Boundaries & Identity
    TRUST_BOUNDARY = "trust_boundary"
    AUTHN_BOUNDARY = "authentication_boundary"
    AUTHZ_BOUNDARY = "authorization_boundary"
    TENANT_BOUNDARY = "tenant_boundary"
    ROLE_CHECK = "role_check"
    OWNERSHIP_CHECK = "ownership_check"

    # Sensitive Sinks / Operations
    DB_OPERATION = "database_operation"
    RAW_QUERY_SINK = "raw_query_sink"
    FS_OPERATION = "filesystem_operation"
    FILE_WRITE_SINK = "file_write_sink"
    COMMAND_OPERATION = "command_process_operation"
    EVAL_OPERATION = "eval_reflection_operation"
    DESERIALIZATION_OPERATION = "deserialization_operation"
    NETWORK_OPERATION = "network_operation"
    CRYPTO_OPERATION = "cryptographic_operation"
    SECRET_EXPOSURE = "secret_credential_exposure"
    RESOURCE_CONSUMPTION = "resource_consumption_operation"
    RESPONSE_RENDER_SINK = "response_render_sink"  # XSS

    # Security Controls & Sanitizers
    INPUT_VALIDATION = "input_validation"
    SANITIZATION = "sanitization"
    RATE_LIMIT_CONTROL = "rate_limit_control"
    ENCRYPTION_CONTROL = "encryption_control"
    ERROR_HANDLING_CONTROL = "error_handling_control"


class BoundaryType(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TENANT_ISOLATION = "tenant_isolation"
    ROLE_BASED = "role_based"
    NETWORK_PUBLIC_PRIVATE = "network_public_private"
    SANDBOX = "sandbox"


@dataclass
class SecurityNode:
    """A canonical security-relevant element abstracted from source code."""
    node_id: str
    concept: SecurityConceptType
    language: str
    file_path: str
    start_line: int
    end_line: int
    raw_code: str
    symbol_name: Optional[str] = None
    enclosing_function: str = "module"
    enclosing_class: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "concept": self.concept.value,
            "language": self.language,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "symbol_name": self.symbol_name,
            "enclosing_function": self.enclosing_function,
            "enclosing_class": self.enclosing_class,
            "parameters": self.parameters,
            "attributes": self.attributes,
        }


@dataclass
class SecurityDataFlow:
    """A directed propagation of data between SecurityNodes across functions/files."""
    flow_id: str
    source_node_id: str
    sink_node_id: str
    intermediate_node_ids: List[str] = field(default_factory=list)
    is_cross_file: bool = False
    is_cross_function: bool = False
    transformations: List[str] = field(default_factory=list)
    sanitizers_passed: List[str] = field(default_factory=list)
    guards_bypassed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source_node_id": self.source_node_id,
            "sink_node_id": self.sink_node_id,
            "intermediate_node_ids": self.intermediate_node_ids,
            "is_cross_file": self.is_cross_file,
            "is_cross_function": self.is_cross_function,
            "transformations": self.transformations,
            "sanitizers_passed": self.sanitizers_passed,
            "guards_bypassed": self.guards_bypassed,
        }


@dataclass
class SecurityBoundary:
    """A trust or authorization demarcation in the codebase."""
    boundary_id: str
    boundary_type: BoundaryType
    file_path: str
    line_number: int
    enclosing_function: str
    guard_expression: str
    enforced_roles: List[str] = field(default_factory=list)
    is_explicit: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "boundary_type": self.boundary_type.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "enclosing_function": self.enclosing_function,
            "guard_expression": self.guard_expression,
            "enforced_roles": self.enforced_roles,
            "is_explicit": self.is_explicit,
        }


@dataclass
class UniversalSecurityIR:
    """Universal Security Intermediate Representation for an audited codebase."""
    nodes: Dict[str, SecurityNode] = field(default_factory=dict)
    flows: List[SecurityDataFlow] = field(default_factory=list)
    boundaries: List[SecurityBoundary] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)  # node_ids of ingress
    sensitive_sinks: List[str] = field(default_factory=list)  # node_ids of sinks
    controls: List[str] = field(default_factory=list)  # node_ids of validation/rate-limits

    def add_node(self, node: SecurityNode) -> None:
        self.nodes[node.node_id] = node
        if node.concept in (
            SecurityConceptType.UNTRUSTED_INPUT,
            SecurityConceptType.HTTP_ENDPOINT,
            SecurityConceptType.RPC_ENDPOINT,
            SecurityConceptType.CLI_INPUT,
            SecurityConceptType.ENV_VARIABLE,
        ):
            self.entry_points.append(node.node_id)
        elif node.concept in (
            SecurityConceptType.DB_OPERATION,
            SecurityConceptType.RAW_QUERY_SINK,
            SecurityConceptType.FS_OPERATION,
            SecurityConceptType.FILE_WRITE_SINK,
            SecurityConceptType.COMMAND_OPERATION,
            SecurityConceptType.EVAL_OPERATION,
            SecurityConceptType.DESERIALIZATION_OPERATION,
            SecurityConceptType.NETWORK_OPERATION,
            SecurityConceptType.CRYPTO_OPERATION,
            SecurityConceptType.SECRET_EXPOSURE,
            SecurityConceptType.RESOURCE_CONSUMPTION,
            SecurityConceptType.RESPONSE_RENDER_SINK,
        ):
            self.sensitive_sinks.append(node.node_id)
        elif node.concept in (
            SecurityConceptType.INPUT_VALIDATION,
            SecurityConceptType.SANITIZATION,
            SecurityConceptType.RATE_LIMIT_CONTROL,
            SecurityConceptType.ROLE_CHECK,
            SecurityConceptType.OWNERSHIP_CHECK,
        ):
            self.controls.append(node.node_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_nodes": len(self.nodes),
            "entry_points": len(self.entry_points),
            "sensitive_sinks": len(self.sensitive_sinks),
            "controls": len(self.controls),
            "flows": [f.to_dict() for f in self.flows],
            "boundaries": [b.to_dict() for b in self.boundaries],
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
        }


@dataclass
class SecurityContext:
    """
    Enriched application-level context passed to Model 1 AI Security Analyst.
    Fuses CPG, Security IR, Frameworks, Endpoints, Auth Policies, and Config.
    """
    repository_name: str
    detected_languages: List[str]
    detected_frameworks: List[str]
    architecture_type: str  # 'monolith', 'microservice', 'api_gateway', 'library', 'cli'
    http_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    auth_mechanisms: List[str] = field(default_factory=list)  # 'jwt', 'session', 'oauth2', 'none'
    database_types: List[str] = field(default_factory=list)  # 'postgresql', 'sqlite', 'mongodb'
    dependencies: List[str] = field(default_factory=list)
    configuration_files: List[str] = field(default_factory=list)
    deterministic_rule_findings: List[Dict[str, Any]] = field(default_factory=list)
    security_ir: Optional[UniversalSecurityIR] = None

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository_name,
            "languages": self.detected_languages,
            "frameworks": self.detected_frameworks,
            "architecture": self.architecture_type,
            "endpoint_count": len(self.http_endpoints),
            "auth_mechanisms": self.auth_mechanisms,
            "database_types": self.database_types,
            "rule_finding_count": len(self.deterministic_rule_findings),
            "ir_stats": {
                "nodes": len(self.security_ir.nodes) if self.security_ir else 0,
                "flows": len(self.security_ir.flows) if self.security_ir else 0,
                "boundaries": len(self.security_ir.boundaries) if self.security_ir else 0,
            },
        }
