"""
Rule: Path Traversal (CWE-22)

Detects user-controlled input flowing into file-open or path-construction
calls. Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler (decorator: @*.tool,
            @*.call_tool) or whose name suggests it is a tool handler
            (contains "tool", "handle", "execute", "handler").

  MEDIUM — function contains a path operation with user input but gives no
            clear signal that it is an MCP tool handler (unknown context).

  NOT FLAGGED — function is classified as "safe" by TaintVisitor:
    • __init__ / __new__ / __post_init__
    • Decorated with @classmethod, @staticmethod, @property
    • Decorated with a CLI framework decorator (@click.command, @typer.command)
    • Name starts with "test_"
    • Resides in a safe directory (cli, commands, config, utilities, utils, auth, etc.)

Dangerous sinks:
  - open(tainted) / io.open(tainted)       — direct file open
  - os.open(tainted, ...)                  — low-level file open
  - Path(tainted) / pathlib.Path(tainted)  — path construction
  - os.path.join(base, tainted, ...)       — any non-first arg tainted

Limitations: alias imports (e.g. `from pathlib import Path as P`) and chained
calls (e.g. `Path(x).open()`) beyond the immediate builtin-sink check are not
tracked.
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

_BUILTIN_SINKS: frozenset[str] = frozenset({"open", "Path"})

_ATTR_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("io", "open"),
    ("os", "open"),
    ("pathlib", "Path"),
})

_TRIPLE_SINKS: frozenset[tuple[str, str, str]] = frozenset({
    ("os", "path", "join"),
})


def check_path_traversal(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches a file-path sink."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Sink detection
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        # Builtin-name sinks: open(x), Path(x)
        if isinstance(node.func, ast.Name) and node.func.id in _BUILTIN_SINKS:
            self._check_first_arg(node, f"{node.func.id}()")

        pair = self._attr_pair(node)
        if pair is not None and pair in _ATTR_SINKS:
            self._check_first_arg(node, f"{pair[0]}.{pair[1]}()")

        triple = self._attr_triple(node)
        if triple is not None and triple in _TRIPLE_SINKS:
            self._check_join_args(node)

        self.generic_visit(node)

    def _check_first_arg(self, node: ast.Call, label: str) -> None:
        if not (node.args and self._is_tainted(node.args[0])):
            return
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-22",
            rule_id="path_traversal",
            description=(
                f"User-controlled input passed to {label}; "
                "an attacker may read or write arbitrary files via path traversal."
            ),
            remediation=(
                "Resolve the path with Path(user_input).resolve() and verify it "
                "starts with the intended base directory before opening."
            ),
        ))

    def _check_join_args(self, node: ast.Call) -> None:
        """Flag os.path.join when any non-first argument is tainted (always HIGH)."""
        if self._current_context() == "safe":
            return
        for arg in node.args[1:]:
            if self._is_tainted(arg):
                self.findings.append(Finding(
                    file_path=self.file_path,
                    line=node.lineno,
                    severity="high",
                    cwe_id="CWE-22",
                    rule_id="path_traversal",
                    description=(
                        "User-controlled input in a non-base argument to os.path.join(); "
                        "an attacker can inject '../' sequences to escape the base directory."
                    ),
                    remediation=(
                        "After joining, call Path(result).resolve() and assert the result "
                        "starts with the expected base directory."
                    ),
                ))
                return  # one finding per call site is enough
