# app/analysis/cpg_engine.py

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CPGNode:
    id: str
    label: str
    node_type: str  # 'source', 'sink', 'sanitizer', 'call', 'branch', 'assign'
    file_path: str
    line_number: int
    code_snippet: str
    data_type: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CPGEdge:
    source_id: str
    target_id: str
    edge_type: str  # 'AST', 'CFG', 'DFG'
    label: Optional[str] = None


class CodePropertyGraph:
    """Unified Code Property Graph (CPG) merging AST, CFG, and DFG representations."""

    def __init__(self):
        self.nodes: Dict[str, CPGNode] = {}
        self.edges: List[CPGEdge] = []
        self._node_counter = 0

    def add_node(
        self,
        label: str,
        node_type: str,
        file_path: str,
        line_number: int,
        code_snippet: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> CPGNode:
        self._node_counter += 1
        node_id = f"n{self._node_counter}"
        node = CPGNode(
            id=node_id,
            label=label,
            node_type=node_type,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet.strip(),
            properties=properties or {},
        )
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id: str, target_id: str, edge_type: str, label: Optional[str] = None):
        self.edges.append(CPGEdge(source_id, target_id, edge_type, label))

    def find_flows_to_sinks(self) -> List[Tuple[CPGNode, CPGNode, List[str]]]:
        """Traces Data Flow Graph (DFG) paths from Sources to Sinks."""
        sources = [n for n in self.nodes.values() if n.node_type == "source"]
        sinks = [n for n in self.nodes.values() if n.node_type == "sink"]
        
        # Build adjacency for DFG
        adj: Dict[str, List[str]] = {}
        for edge in self.edges:
            if edge.edge_type in ("DFG", "CFG"):
                adj.setdefault(edge.source_id, []).append(edge.target_id)

        flows: List[Tuple[CPGNode, CPGNode, List[str]]] = []

        for source in sources:
            visited: Set[str] = set()
            queue: List[Tuple[str, List[str]]] = [(source.id, [source.id])]

            while queue:
                current_id, path = queue.pop(0)
                if current_id in visited:
                    continue
                visited.add(current_id)

                curr_node = self.nodes.get(current_id)
                if curr_node and curr_node.node_type == "sink" and current_id != source.id:
                    flows.append((source, curr_node, path))
                    continue

                for neighbor_id in adj.get(current_id, []):
                    if neighbor_id not in visited:
                        queue.append((neighbor_id, path + [neighbor_id]))

        return flows


class CPGEngine:
    """Universal Code Property Graph extractor across Python, JS/TS, C/C++, Rust, and Go."""

    # Multi-language vulnerability sink signatures
    SINKS_BY_LANG = {
        "python": {
            "sql": ["execute", "executemany", "raw_query"],
            "command": ["subprocess.run", "subprocess.Popen", "os.system", "os.popen", "exec"],
            "path": ["open", "os.remove", "os.unlink", "shutil.rmtree"],
            "deser": ["pickle.loads", "yaml.load", "marshal.loads"],
        },
        "javascript": {
            "sql": ["query", "raw", "execute"],
            "command": ["exec", "spawn", "execSync", "spawnSync"],
            "path": ["fs.readFile", "fs.writeFile", "fs.unlink"],
            "eval": ["eval", "Function", "vm.runInContext"],
        },
        "c_cpp": {
            "memory": ["strcpy", "strcat", "sprintf", "gets", "memcpy"],
            "command": ["system", "popen", "execve", "execl"],
            "format": ["printf", "fprintf", "syslog"],
        },
        "rust": {
            "unsafe": ["unsafe", "transmute", "from_raw_parts"],
            "command": ["Command::new"],
        },
        "go": {
            "sql": ["Query", "Exec", "QueryRow"],
            "command": ["exec.Command"],
        },
    }

    # Sources by language
    SOURCES_BY_LANG = {
        "python": ["request.args", "request.form", "request.json", "sys.argv", "input", "environ.get"],
        "javascript": ["req.query", "req.body", "req.params", "process.argv", "req.headers"],
        "c_cpp": ["argv", "getenv", "recv", "read", "fgets", "scanf"],
        "rust": ["std::env::args", "request.query()", "request.body()"],
        "go": ["r.URL.Query()", "r.FormValue", "os.Args", "r.Body"],
    }

    def build_workspace_cpg(self, workspace_path: Path) -> CodePropertyGraph:
        cpg = CodePropertyGraph()
        
        for root, _, files in os.walk(workspace_path):
            for file_name in files:
                file_path = Path(root) / file_name
                lang = self._detect_language(file_name)
                if not lang:
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    self._parse_file_into_cpg(cpg, str(file_path.relative_to(workspace_path)), content, lang)
                except Exception:
                    continue

        return cpg

    def _detect_language(self, file_name: str) -> Optional[str]:
        ext = Path(file_name).suffix.lower()
        if ext == ".py":
            return "python"
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
            return "javascript"
        elif ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"):
            return "c_cpp"
        elif ext == ".rs":
            return "rust"
        elif ext == ".go":
            return "go"
        elif ext == ".java":
            return "java"
        return None

    def _parse_file_into_cpg(
        self, cpg: CodePropertyGraph, rel_path: str, content: str, lang: str
    ):
        if lang == "python":
            self._parse_python(cpg, rel_path, content)
        else:
            self._parse_generic_lexical(cpg, rel_path, content, lang)

    def _parse_python(self, cpg: CodePropertyGraph, rel_path: str, content: str):
        try:
            tree = ast.parse(content)
        except SyntaxError:
            self._parse_generic_lexical(cpg, rel_path, content, "python")
            return

        for node in ast.walk(tree):
            line_no = getattr(node, "lineno", 1)
            code_str = ast.unparse(node) if hasattr(ast, "unparse") else ""

            # Detect Sources
            if isinstance(node, (ast.Attribute, ast.Name, ast.Call)):
                node_text = ast.unparse(node) if hasattr(ast, "unparse") else ""
                if any(src in node_text for src in self.SOURCES_BY_LANG.get("python", [])):
                    cpg.add_node(
                        label=f"Source: {node_text[:30]}",
                        node_type="source",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=node_text,
                    )

            # Detect Sinks
            if isinstance(node, ast.Call):
                func_str = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
                for sink_cat, sink_fns in self.SINKS_BY_LANG.get("python", {}).items():
                    if any(fn in func_str for fn in sink_fns):
                        cpg.add_node(
                            label=f"Sink ({sink_cat}): {func_str}",
                            node_type="sink",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=code_str[:80],
                            properties={"category": sink_cat},
                        )

    def _parse_generic_lexical(
        self, cpg: CodePropertyGraph, rel_path: str, content: str, lang: str
    ):
        lines = content.splitlines()
        sources = self.SOURCES_BY_LANG.get(lang, [])
        sinks_dict = self.SINKS_BY_LANG.get(lang, {})

        for line_idx, line in enumerate(lines, start=1):
            trimmed = line.strip()
            if not trimmed or trimmed.startswith(("//", "/*", "#", "*")):
                continue

            # Check Sources
            for src in sources:
                if src in trimmed:
                    cpg.add_node(
                        label=f"Source: {src}",
                        node_type="source",
                        file_path=rel_path,
                        line_number=line_idx,
                        code_snippet=trimmed[:80],
                    )

            # Check Sinks
            for sink_cat, sink_fns in sinks_dict.items():
                for fn in sink_fns:
                    if fn in trimmed:
                        cpg.add_node(
                            label=f"Sink ({sink_cat}): {fn}",
                            node_type="sink",
                            file_path=rel_path,
                            line_number=line_idx,
                            code_snippet=trimmed[:80],
                            properties={"category": sink_cat},
                        )
