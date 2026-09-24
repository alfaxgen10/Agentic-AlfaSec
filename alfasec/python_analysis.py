"""Conservative, standard-library Python source-to-sink analysis."""
from __future__ import annotations

import ast
from pathlib import Path

from .models import EngineResult, Finding, ScanRequest
from .rules import IGNORED_DIRECTORIES


_SOURCE_ATTRIBUTES = {"args", "query_params", "body", "form", "json"}
_COMMANDS = {"os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "eval", "exec"}
_SQL_METHODS = {"execute"}
_PATH_CALLS = {"open", "os.remove", "pathlib.Path", "Path"}
_DESERIALIZERS = {"pickle.loads", "pickle.load", "yaml.load"}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


class _PythonFlowVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, tree: ast.AST, source_lines: list[str]):
        self.path, self.tree, self.lines = path, tree, source_lines
        self.aliases: dict[str, str] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.tainted: set[str] = set()
        self.constant_names: set[str] = set()
        self.tainted_params: set[tuple[str, str]] = set()
        self.findings: list[Finding] = []
        self._reported: set[tuple[str, int]] = set()
        for item in ast.walk(tree):
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[item.name] = item
            elif isinstance(item, ast.Import):
                for alias in item.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(item, ast.ImportFrom):
                for alias in item.names:
                    self.aliases[alias.asname or alias.name] = f"{item.module or ''}.{alias.name}".strip(".")

    def _expr_name(self, node: ast.AST) -> str:
        name = _dotted(node)
        if not name:
            return ""
        first, _, rest = name.partition(".")
        return f"{self.aliases.get(first, first)}.{rest}" if rest else self.aliases.get(first, first)

    def _is_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and (_dotted(node.func) in {"input", "builtins.input"}):
            return True
        if isinstance(node, ast.Attribute) and node.attr in _SOURCE_ATTRIBUTES:
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return node.func.attr in {"get", "get_json", "json"} and self._is_source(node.func.value)
        return False

    def _tainted(self, node: ast.AST) -> bool:
        if self._is_source(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return any(self._tainted(child) for child in ast.iter_child_nodes(node))
        if isinstance(node, ast.Call):
            # Known sanitizers and parameterized query values do not remain tainted.
            name = self._expr_name(node.func)
            if name in {"shlex.quote", "os.path.basename", "werkzeug.utils.escape"}:
                return False
            return any(self._tainted(arg) for arg in node.args) or any(
                self._tainted(keyword.value) for keyword in node.keywords
            )
        return any(self._tainted(child) for child in ast.iter_child_nodes(node))

    def _static(self, node: ast.AST) -> bool:
        """Whether an expression is known not to contain runtime input."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.constant_names
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return all(self._static(child) for child in ast.iter_child_nodes(node))
        return False

    def _finding(self, rule: str, title: str, cwe: str, node: ast.AST, remediation: str, evidence: str) -> None:
        line = getattr(node, "lineno", 1)
        key = (rule, line)
        if key in self._reported:
            return
        self._reported.add(key)
        self.findings.append(Finding(
            rule, title, "HIGH" if rule != "python-weak-hash" else "MEDIUM", "high",
            cwe, None, "context-dependent", str(self.path), line,
            evidence[:300], remediation,
        ))

    def _sink(self, node: ast.Call) -> None:
        name = self._expr_name(node.func)
        args_tainted = [arg for arg in node.args if self._tainted(arg)]
        if name in _COMMANDS and args_tainted:
            self._finding("python-command-injection", "Tainted input reaches command execution",
                          "CWE-78", node, "Avoid shell execution; use fixed argument lists and strict allowlists.",
                          f"tainted input -> {name} (line {node.lineno})")
        if name in _DESERIALIZERS and args_tainted:
            self._finding("python-unsafe-deserialization", "Tainted input reaches unsafe deserialization",
                          "CWE-502", node, "Use a safe data format/parser and never unpickle untrusted data.",
                          f"tainted input -> {name} (line {node.lineno})")
        if name in _PATH_CALLS and args_tainted:
            self._finding("python-path-traversal", "Tainted input reaches a filesystem path",
                          "CWE-22", node, "Resolve paths below a fixed base directory and reject traversal.",
                          f"tainted input -> {name} (line {node.lineno})")
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "write_text"} and self._tainted(node.func.value):
            self._finding("python-path-traversal", "Tainted input reaches a filesystem path",
                          "CWE-22", node, "Resolve paths below a fixed base directory and reject traversal.",
                          f"tainted path -> {name} (line {node.lineno})")
        if isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_METHODS and args_tainted:
            # A query with bound parameters is safe when the query itself is constant.
            if len(node.args) > 1 and self._static(node.args[0]):
                return
            self._finding("python-sql-injection", "Tainted input reaches a SQL query",
                          "CWE-89", node, "Use parameterized queries and bind values separately.",
                          f"tainted input -> {name} (line {node.lineno})")
        if name in {"hashlib.md5", "hashlib.sha1"}:
            self._finding("python-weak-hash", "Weak cryptographic hash algorithm",
                          "CWE-327", node, "Use SHA-256 or a modern password-hashing algorithm such as Argon2id.",
                          f"weak hash: {name} (line {node.lineno})")

    def visit_Import(self, node: ast.Import) -> None:
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
                    self.constant_names.discard(target.id)
        elif self._static(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.constant_names.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and self._tainted(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._sink(node)
        called = _dotted(node.func)
        if called in self.functions:
            function = self.functions[called]
            positional = list(function.args.args)
            for parameter, argument in zip(positional, node.args):
                if self._tainted(argument):
                    self.tainted.add(parameter.arg)
                    self.tainted_params.add((called, parameter.arg))
        self.generic_visit(node)


def scan_python_ast(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return []
    visitor = _PythonFlowVisitor(path, tree, text.splitlines())
    # Revisit so calls appearing before their helper invocation still receive taint.
    for _ in range(4):
        visitor.visit(tree)
    return visitor.findings


def scan_python_project(root: Path) -> list[Finding]:
    paths = [root] if root.is_file() else root.rglob("*.py")
    findings: list[Finding] = []
    for path in paths:
        if path.is_file() and path.stat().st_size <= 2_000_000 and not any(
            part in IGNORED_DIRECTORIES for part in path.parts
        ):
            findings.extend(scan_python_ast(path))
    return findings


class PythonAstEngine:
    engine_id = "python-ast"

    def run(self, request: ScanRequest) -> EngineResult:
        try:
            return EngineResult(self.engine_id, scan_python_project(request.scope.root),
                                {"mode": "stdlib ast source-to-sink data-flow"}, [])
        except OSError as error:
            return EngineResult(self.engine_id, [], {}, [str(error)])
