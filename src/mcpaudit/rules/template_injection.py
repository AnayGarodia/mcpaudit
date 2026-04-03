"""
Rule: Template Injection (CWE-94)

Detects user-controlled input flowing into template engine constructors,
allowing attackers to execute arbitrary code via server-side template injection
(SSTI).

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, auth, etc.).

Dangerous sinks:
  - jinja2.Template(tainted)               — creates template from user input
  - jinja2.Environment().from_string(tainted) — renders user-supplied template
  - mako.template.Template(tainted)        — Mako template from user input
  - Template(tainted)  where Template was imported from jinja2 or mako

Safe patterns (NOT flagged):
  - env.get_template("name.html")          — loads static template by name
  - template.render(user_input=value)      — renders with context, not injected
  - jinja2.Template("static string")       — static template (no taint)
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# Module.constructor pairs that are template injection sinks.
_TEMPLATE_ATTR_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("jinja2", "Template"),
    ("mako", "Template"),
})

# Module.attr.method triple patterns: e.g. jinja2.Environment().from_string(...)
# We detect these by checking that the call is .from_string on a jinja2.Environment obj.
_FROM_STRING_SINKS: frozenset[str] = frozenset({"from_string"})

# Module/package names that, when Template is imported from them, make Template() dangerous.
_DANGEROUS_TEMPLATE_MODULES: frozenset[str] = frozenset({
    "jinja2", "mako", "mako.template",
})


def check_template_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches a template constructor."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Names imported directly from jinja2/mako that are template constructors.
        self._dangerous_constructors: set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track `from jinja2 import Template` style imports."""
        super().visit_ImportFrom(node)
        module = node.module or ""
        if module in _DANGEROUS_TEMPLATE_MODULES:
            for alias in node.names:
                if alias.name == "Template":
                    bound = alias.asname if alias.asname else alias.name
                    self._dangerous_constructors.add(bound)

    def visit_Call(self, node: ast.Call) -> None:
        # Pattern 1: jinja2.Template(tainted) or mako.Template(tainted)
        pair = self._resolved_attr_pair(node)
        if pair is not None and pair in _TEMPLATE_ATTR_SINKS:
            if node.args and self._is_tainted(node.args[0]):
                self._report(node, f"{pair[0]}.{pair[1]}()")

        # Pattern 2: env.from_string(tainted) where env is a jinja2.Environment instance.
        # Detect: <anything>.from_string(tainted_first_arg).
        # We flag any .from_string call with a tainted first arg as a potential SSTI,
        # since from_string is almost exclusively used with Jinja2/Mako environments.
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _FROM_STRING_SINKS
            and node.args
            and self._is_tainted(node.args[0])
        ):
            self._report(node, "Environment.from_string()")

        # Pattern 3: Template(tainted) where Template was imported from jinja2/mako.
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self._dangerous_constructors
            and node.args
            and self._is_tainted(node.args[0])
        ):
            self._report(node, f"{node.func.id}()")

        self.generic_visit(node)

    def _report(self, node: ast.Call, label: str) -> None:
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-94",
            rule_id="template_injection",
            description=(
                f"User-controlled input passed to {label}; "
                "an attacker can inject template directives to execute arbitrary code "
                "on the server (Server-Side Template Injection / SSTI)."
            ),
            remediation=(
                "Never construct templates from user-supplied strings. "
                "Load templates from trusted files using env.get_template('name.html') "
                "and pass user data only as render context variables: "
                "template.render(name=user_value)."
            ),
        ))
