"""
Rule: LDAP Injection (CWE-90)

Detects user-controlled input flowing into LDAP search filters without sanitization,
allowing attackers to manipulate directory queries, bypass authentication, or extract
unauthorized directory entries by injecting LDAP metacharacters.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, auth, etc.).

Dangerous sinks:
  - conn.search_s(base, scope, filterstr)  where conn = ldap.initialize(...)
  - conn.search(base, scope, filterstr)    where conn = ldap.initialize(...)
  - conn.search(search_base, search_filter) where conn = ldap3.Connection(...)

Safe patterns (NOT flagged):
  - Static string as filter: conn.search_s(base, scope, "(uid=admin)")
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# Constructor pairs that create an ldap/ldap3 connection object.
# Maps (module, func) → positional index of the filter argument in search calls.
_LDAP_CONN_CONSTRUCTORS: dict[tuple[str, str], int] = {
    ("ldap", "initialize"): 2,   # search_s(base, scope, filterstr) — filter at index 2
    ("ldap", "open"): 2,
    ("ldap3", "Connection"): 1,  # search(search_base, search_filter) — filter at index 1
}

# Search method names on connection objects.
_LDAP_SEARCH_METHODS: frozenset[str] = frozenset({
    "search_s", "search", "search_ext", "search_ext_s",
})

# Keyword argument names used for the filter in ldap3 search calls.
_FILTER_KWARG_NAMES: frozenset[str] = frozenset({
    "filterstr", "search_filter",
})


def check_ldap_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches an LDAP search filter."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Maps connection variable name → filter positional arg index.
        self._conn_filter_idx: dict[str, int] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track ldap/ldap3 connection variable assignments."""
        if isinstance(node.value, ast.Call):
            pair = self._resolved_attr_pair(node.value)
            if pair is not None and pair in _LDAP_CONN_CONSTRUCTORS:
                idx = _LDAP_CONN_CONSTRUCTORS[pair]
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._conn_filter_idx[target.id] = idx
        super().visit_Assign(node)

    def visit_Call(self, node: ast.Call) -> None:
        pair = self._resolved_attr_pair(node)
        if pair is not None and pair[0] in self._conn_filter_idx:
            mod, method = pair
            if method in _LDAP_SEARCH_METHODS:
                filter_idx = self._conn_filter_idx[mod]
                # Check positional filter argument.
                if len(node.args) > filter_idx and self._is_tainted(node.args[filter_idx]):
                    self._report(node, f"connection.{method}()", "filter argument")
                else:
                    # Check keyword filter argument.
                    for kw in node.keywords:
                        if kw.arg in _FILTER_KWARG_NAMES and self._is_tainted(kw.value):
                            self._report(node, f"connection.{method}()", kw.arg)
                            break

        self.generic_visit(node)

    def _report(self, node: ast.Call, label: str, param: str) -> None:
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-90",
            rule_id="ldap_injection",
            description=(
                f"User-controlled input passed as {param} to {label}; "
                "an attacker can inject LDAP metacharacters to alter the search filter, "
                "bypass authentication, or access unauthorized directory entries."
            ),
            remediation=(
                "Escape special LDAP characters in user input before using it in a filter. "
                "With python-ldap use ldap.filter.escape_filter_chars(). "
                "With ldap3 use ldap3.utils.conv.escape_filter_chars(). "
                "Validate input against a strict allowlist of permitted characters."
            ),
        ))
