"""
Rule: Shell Injection (CWE-78)

Detects user-controlled input flowing into subprocess calls with shell=True,
or into os.system / os.popen, without prior validation.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, utils, etc.).

Dangerous sinks:
  - subprocess.run/Popen/call/check_output/check_call with shell=True
  - os.system / os.popen (always execute via shell)

Alias imports (e.g. `import subprocess as sp`) are tracked via TaintVisitor._resolve_module.
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

_SUBPROCESS_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
})

_OS_SHELL_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("os", "system"),
    ("os", "popen"),
})


def check_shell_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches a shell execution sink."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        pair = self._resolved_attr_pair(node)
        if pair is not None:
            if pair in _SUBPROCESS_SINKS:
                self._check_subprocess_call(node, pair)
            elif pair in _OS_SHELL_SINKS:
                self._check_os_shell_call(node, pair)
        self.generic_visit(node)

    def _check_subprocess_call(self, node: ast.Call, pair: tuple[str, str]) -> None:
        if not self._has_shell_true(node):
            return
        cmd = node.args[0] if node.args else None
        if cmd is None or not self._is_tainted(cmd):
            return
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-78",
            rule_id="shell_injection",
            description=(
                f"User-controlled input passed to {pair[0]}.{pair[1]}() with shell=True; "
                "shell metacharacters in the input will be interpreted by the OS shell."
            ),
            remediation=(
                "Pass arguments as a list (e.g. ['ls', filename]) and omit shell=True. "
                "Validate or allowlist inputs before use."
            ),
        ))

    def _check_os_shell_call(self, node: ast.Call, pair: tuple[str, str]) -> None:
        cmd = node.args[0] if node.args else None
        if cmd is None or not self._is_tainted(cmd):
            return
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-78",
            rule_id="shell_injection",
            description=(
                f"User-controlled input passed to {pair[0]}.{pair[1]}(); "
                "this function always invokes the OS shell."
            ),
            remediation=(
                "Use subprocess.run() with a list of arguments and shell=False. "
                "Validate or allowlist inputs before use."
            ),
        ))

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        """Return True if the call has shell=True as a keyword argument."""
        return any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )
