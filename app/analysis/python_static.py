# app/analysis/python_static.py

import ast

from app.analysis.finding import Finding

# Names that are dangerous to call directly, regardless of arguments.
UNSAFE_CALLS = {
    "eval": ("unsafe-eval", "high", "Use of eval() on potentially untrusted input."),
    "exec": ("unsafe-exec", "high", "Use of exec() on potentially untrusted input."),
    "os.system": ("command-injection-risk", "high", "os.system() call may allow command injection."),
    "pickle.load": ("unsafe-deserialization", "high", "pickle.load() can execute arbitrary code on untrusted data."),
    "pickle.loads": ("unsafe-deserialization", "high", "pickle.loads() can execute arbitrary code on untrusted data."),
    "yaml.load": ("unsafe-deserialization", "medium", "yaml.load() without SafeLoader can execute arbitrary code."),
}

CREDENTIAL_NAME_HINTS = ("password", "passwd", "secret", "api_key", "apikey", "token")


class PythonStaticAnalyzer(ast.NodeVisitor):
    """
    Lightweight AST-based scanner for a curated set of unsafe
    Python patterns. This is the first slice of VAJRA's Static
    Analysis Layer — deterministic, no external tooling required.
    """

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.findings = []
        self._function_stack = []

    def analyze(self):
        tree = ast.parse("\n".join(self.source_lines), filename=self.file_path)
        self.visit(tree)
        return self.findings

    def _current_function(self):
        return self._function_stack[-1] if self._function_stack else "module"

    def _dotted_name(self, node):
        """
        Resolve a Call's func into a dotted string like 'os.system',
        or a plain name like 'eval'. Returns None if it can't be resolved.
        """

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            base = self._dotted_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr

        return None

    def visit_FunctionDef(self, node):
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        dotted = self._dotted_name(node.func)

        if dotted in UNSAFE_CALLS:
            vuln_type, severity, message = UNSAFE_CALLS[dotted]
            self.findings.append(
                Finding(
                    file=self.file_path,
                    line=node.lineno,
                    function=self._current_function(),
                    vulnerability_type=vuln_type,
                    severity=severity,
                    message=message,
                    call_name=dotted,
                )
            )

        # subprocess.*(..., shell=True) is only dangerous with shell=True,
        # so it's checked separately from the static UNSAFE_CALLS table.
        if dotted and dotted.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        Finding(
                            file=self.file_path,
                            line=node.lineno,
                            function=self._current_function(),
                            vulnerability_type="command-injection-risk",
                            severity="high",
                            message=f"{dotted}() called with shell=True.",
                            call_name=dotted,
                        )
                    )

        # SQL Injection detection: cursor.execute / db.execute with formatted strings
        if dotted and (dotted.endswith(".execute") or dotted == "execute"):
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self.findings.append(
                    Finding(
                        file=self.file_path,
                        line=node.lineno,
                        function=self._current_function(),
                        vulnerability_type="sql-injection-risk",
                        severity="high",
                        message=f"{dotted}() called with dynamic string concatenation or f-string.",
                        call_name=dotted,
                    )
                )

        # Path Traversal detection: open(...) with dynamic concatenation or f-string
        if dotted == "open":
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self.findings.append(
                    Finding(
                        file=self.file_path,
                        line=node.lineno,
                        function=self._current_function(),
                        vulnerability_type="path-traversal-risk",
                        severity="high",
                        message="open() called with dynamic path concatenation without containment check.",
                        call_name=dotted,
                    )
                )

        self.generic_visit(node)

    def visit_Assign(self, node):
        # Flag string-literal assignments to variables whose name looks
        # like a credential (e.g. password = "hunter2").
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    lowered = target.id.lower()

                    if any(hint in lowered for hint in CREDENTIAL_NAME_HINTS) and node.value.value:
                        self.findings.append(
                            Finding(
                                file=self.file_path,
                                line=node.lineno,
                                function=self._current_function(),
                                vulnerability_type="hardcoded-credential",
                                severity="medium",
                                message=f"Possible hardcoded credential assigned to '{target.id}'.",
                            )
                        )

        self.generic_visit(node)


def analyze_source(file_path: str, source: str):
    """
    Run the static analyzer over a single Python source string.
    Returns a list of Finding objects. Files with syntax errors
    are skipped (reported as a single low-severity finding)
    rather than crashing the whole scan.
    """

    try:
        return PythonStaticAnalyzer(file_path, source).analyze()
    except SyntaxError as exc:
        return [
            Finding(
                file=file_path,
                line=exc.lineno or 0,
                vulnerability_type="parse-error",
                severity="low",
                message=f"Could not parse file: {exc.msg}",
            )
        ]


def analyze_file(file_path: str):
    """
    Run the static analyzer over a Python file on disk.
    """

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()

    return analyze_source(file_path, source)