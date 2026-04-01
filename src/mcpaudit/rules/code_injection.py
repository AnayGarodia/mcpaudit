"""
Rule: Code Injection via eval/exec (CWE-95)

Detects user-controlled input flowing into Python's eval() or exec() builtins,
which execute arbitrary Python code at runtime.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, utils, etc.).

Dangerous sinks:
  - eval(tainted)
  - exec(tainted)

Limitations: alias imports (e.g. `e = eval; e(x)`) are not tracked.
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

_CODE_SINKS: frozenset[str] = frozenset({"eval", "exec"})


def check_code_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches eval() or exec()."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in _CODE_SINKS
            and node.args
            and self._is_tainted(node.args[0])
        ):
            ctx = self._current_context()
            if ctx != "safe":
                severity = "high" if ctx == "tool" else "medium"
                self.findings.append(Finding(
                    file_path=self.file_path,
                    line=node.lineno,
                    severity=severity,
                    cwe_id="CWE-95",
                    rule_id="code_injection",
                    description=(
                        f"User-controlled input passed to {node.func.id}(); "
                        "this executes arbitrary Python code supplied by the caller."
                    ),
                    remediation=(
                        f"Do not pass user input to {node.func.id}(). "
                        "Use a safe alternative such as ast.literal_eval() for data parsing, "
                        "or restrict inputs to a well-defined allowlist."
                    ),
                ))
        self.generic_visit(node)
