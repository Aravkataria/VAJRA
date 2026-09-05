# tests/test_security_ir.py

import tempfile
from pathlib import Path
import pytest

from app.analysis.security_ir.schema import (
    BoundaryType,
    SecurityBoundary,
    SecurityConceptType,
    SecurityContext,
    SecurityDataFlow,
    SecurityNode,
    UniversalSecurityIR,
)
from app.analysis.security_ir.taxonomy import TAXONOMY_REGISTRY, lookup_taxonomy
from app.analysis.security_ir.extractor import SecurityIRExtractor


def test_taxonomy_registry():
    assert len(TAXONOMY_REGISTRY) >= 20
    assert "broken_object_level_authorization" in TAXONOMY_REGISTRY
    assert "sql_injection" in TAXONOMY_REGISTRY
    assert "missing_rate_limiting" in TAXONOMY_REGISTRY

    # Check alias lookup
    tax_idor = lookup_taxonomy("idor")
    assert tax_idor is not None
    assert tax_idor.cwe_id == "CWE-639"

    tax_sqli = lookup_taxonomy("SQLi")
    assert tax_sqli is not None
    assert tax_sqli.cwe_id == "CWE-89"


def test_security_ir_data_classes():
    ir = UniversalSecurityIR()
    node1 = SecurityNode(
        node_id="n1",
        concept=SecurityConceptType.UNTRUSTED_INPUT,
        language="python",
        file_path="routes/auth.py",
        start_line=10,
        end_line=10,
        raw_code="username = request.form['username']",
    )
    node2 = SecurityNode(
        node_id="n2",
        concept=SecurityConceptType.RAW_QUERY_SINK,
        language="python",
        file_path="routes/auth.py",
        start_line=15,
        end_line=15,
        raw_code="db.execute(f'SELECT * FROM users WHERE name={username}')",
    )
    ir.add_node(node1)
    ir.add_node(node2)

    assert len(ir.entry_points) == 1
    assert len(ir.sensitive_sinks) == 1

    flow = SecurityDataFlow(
        flow_id="f1",
        source_node_id="n1",
        sink_node_id="n2",
        is_cross_file=False,
    )
    ir.flows.append(flow)

    ir_dict = ir.to_dict()
    assert ir_dict["total_nodes"] == 2
    assert len(ir_dict["flows"]) == 1


def test_security_ir_extractor_multilingual():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # Python file
        py_file = tmp_path / "app.py"
        py_file.write_text(
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    user = request.form['user']\n"
            "    db.execute(user)\n"
            "    return 'ok'\n"
        )

        # TypeScript file
        ts_file = tmp_path / "api.ts"
        ts_file.write_text(
            "app.get('/user/:id', async (req, res) => {\n"
            "    const id = req.params.id;\n"
            "    const data = await fs.readFile(id);\n"
            "    res.send(data);\n"
            "});\n"
        )

        extractor = SecurityIRExtractor()
        context = extractor.extract_workspace(tmp_path)

        assert "python" in context.detected_languages
        assert "typescript" in context.detected_languages
        assert len(context.http_endpoints) == 2
        assert context.security_ir is not None
        assert len(context.security_ir.nodes) > 0
