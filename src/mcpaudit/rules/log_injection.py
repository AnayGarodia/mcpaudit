"""
Rule: Log Injection (CWE-117)

Detects user-controlled input passed directly as the log message to standard
logging functions, allowing attackers to inject fake log entries by embedding
newlines or ANSI escape sequences. This corrupts log integrity and can mislead
security monitoring and incident response.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, auth, etc.).

Dangerous sinks (first positional argument is tainted):
  - logging.info/debug/warning/error/critical/exception/log(tainted_message)
  - logger.info/debug/warning/error/critical/exception/log(tainted_message)
    where logger was assigned from logging.getLogger()

Safe patterns (NOT flagged):
  - logging.info("static: %s", user_input)  — static format string as first arg
  - logging.info("static message")          — no user-controlled data in message
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# Logging method names that write a log record.
_LOG_METHODS: frozenset[str] = frozenset({
    "debug", "info", "warning", "warn", "error", "critical", "exception", "log",
})

# (module, function) pairs that produce a Logger instance.
_LOGGER_CONSTRUCTORS: frozenset[tuple[str, str]] = frozenset({
    ("logging", "getLogger"),
    ("logging", "Logger"),
})


def check_log_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input is the log message."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Names of variables assigned from logging.getLogger() or similar.
        self._logger_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track logger variable assignments (module-level and local)."""
        if isinstance(node.value, ast.Call):
            pair = self._resolved_attr_pair(node.value)
            if pair is not None and pair in _LOGGER_CONSTRUCTORS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._logger_vars.add(target.id)
        super().visit_Assign(node)

    def visit_Call(self, node: ast.Call) -> None:
        pair = self._resolved_attr_pair(node)
        if pair is not None:
            mod, method = pair
            if method in _LOG_METHODS:
                # Pattern 1: logging.info(tainted), logging.warning(tainted), etc.
                if mod == "logging":
                    self._check_log_call(node, f"logging.{method}()")
                # Pattern 2: logger.info(tainted) — logger from getLogger()
                elif mod in self._logger_vars:
                    self._check_log_call(node, f"<logger>.{method}()")

        self.generic_visit(node)

    def _check_log_call(self, node: ast.Call, label: str) -> None:
        """Flag if the first positional argument (the message/format) is tainted.

        Parameterized calls like `logging.info("msg: %s", user_val)` are NOT
        flagged because the first arg is a static format string.
        """
        if not node.args:
            return
        if not self._is_tainted(node.args[0]):
            return
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-117",
            rule_id="log_injection",
            description=(
                f"User-controlled input passed as the message to {label}; "
                "an attacker can embed newlines or ANSI escape sequences to inject "
                "fake log entries and corrupt log integrity."
            ),
            remediation=(
                "Use parameterized logging so the format string stays static: "
                "`logging.info('Received: %s', user_input)`. "
                "Strip or encode newlines and control characters from user input "
                "before logging: user_input.replace('\\n', ' ').replace('\\r', ' '). "
                "Configure log formatters to escape special characters."
            ),
        ))
