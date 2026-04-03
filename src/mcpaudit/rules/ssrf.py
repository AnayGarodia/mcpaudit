"""
Rule: Server-Side Request Forgery (CWE-918)

Detects user-controlled input flowing into HTTP request functions as the URL
argument, allowing an attacker to make the server issue requests to arbitrary
internal or external hosts.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, auth, etc.).

Dangerous sinks:
  - requests.get/post/put/delete/patch/head/request(url, ...)
  - httpx.get/post/put/delete/patch/head/request(url, ...)
  - urllib.request.urlopen(url, ...)
  - session.get/post/put/delete/patch/head/request(url, ...) where session is
    assigned from requests.Session(), httpx.Client(), httpx.AsyncClient(), or
    aiohttp.ClientSession()

The URL may be passed positionally (first arg) or as the `url=` keyword.
"""
import ast
import re

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# Matches a fixed scheme + host prefix at the start of an f-string constant part,
# e.g. "https://api.example.com/" — the host is hardcoded, so the user can only
# influence the path, not the destination host.  That is path injection, not SSRF.
_FIXED_HOST_RE = re.compile(r"^https?://[a-zA-Z0-9._-]+(?:/|$)")

_HTTP_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("requests", "get"), ("requests", "post"), ("requests", "put"),
    ("requests", "delete"), ("requests", "patch"), ("requests", "head"),
    ("requests", "request"),
    ("httpx", "get"), ("httpx", "post"), ("httpx", "put"),
    ("httpx", "delete"), ("httpx", "patch"), ("httpx", "head"),
    ("httpx", "request"),
})

_TRIPLE_SINKS: frozenset[tuple[str, str, str]] = frozenset({
    ("urllib", "request", "urlopen"),
})

# Constructors that produce HTTP session objects.
_SESSION_CONSTRUCTORS: frozenset[tuple[str, str]] = frozenset({
    ("requests", "Session"),
    ("httpx", "Client"),
    ("httpx", "AsyncClient"),
    ("aiohttp", "ClientSession"),
})

# Methods on session objects that accept a URL as first positional arg.
_SESSION_METHODS: frozenset[str] = frozenset({
    "get", "post", "put", "delete", "patch", "head", "request",
})


def check_ssrf(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches an HTTP request sink."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Variable names assigned from session constructors (per module scope).
        self._session_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track session variable assignments AND propagate taint."""
        # Check if RHS is a session constructor call.
        if isinstance(node.value, ast.Call):
            pair = self._resolved_attr_pair(node.value)
            if pair is not None and pair in _SESSION_CONSTRUCTORS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._session_vars.add(target.id)
        # Delegate to parent for taint propagation.
        super().visit_Assign(node)

    def visit_Call(self, node: ast.Call) -> None:
        pair = self._resolved_attr_pair(node)
        if pair is not None and pair in _HTTP_SINKS:
            self._check_url_arg(node, f"{pair[0]}.{pair[1]}()")
        elif pair is not None and pair[0] in self._session_vars and pair[1] in _SESSION_METHODS:
            self._check_url_arg(node, f"<session>.{pair[1]}()")

        triple = self._resolved_attr_triple(node)
        if triple is not None and triple in _TRIPLE_SINKS:
            self._check_url_arg(node, "urllib.request.urlopen()")

        self.generic_visit(node)

    def _check_url_arg(self, node: ast.Call, label: str) -> None:
        """Flag when the URL argument (positional or url= keyword) is tainted."""
        ctx = self._current_context()
        if ctx == "safe":
            return

        if node.args and self._is_tainted(node.args[0]):
            if not self._url_has_fixed_host(node.args[0]):
                self._report(node, label, ctx)
            return
        # Check for url= keyword when not passed positionally.
        if not node.args:
            for kw in node.keywords:
                if kw.arg == "url" and self._is_tainted(kw.value):
                    if not self._url_has_fixed_host(kw.value):
                        self._report(node, label, ctx)
                    return

    @staticmethod
    def _url_has_fixed_host(node: ast.expr) -> bool:
        """Return True if the URL starts with a hardcoded scheme+host.

        e.g. f"https://api.example.com/{endpoint}" — the attacker can only
        control the path, not the host, so this is not exploitable SSRF.
        """
        if not isinstance(node, ast.JoinedStr) or not node.values:
            return False
        first = node.values[0]
        return (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and bool(_FIXED_HOST_RE.match(first.value))
        )

    def _report(self, node: ast.Call, label: str, ctx: str) -> None:
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-918",
            rule_id="ssrf",
            description=(
                f"User-controlled input passed as the URL to {label}; "
                "an attacker can redirect the request to internal services or arbitrary hosts."
            ),
            remediation=(
                "Validate the URL against an allowlist of permitted hosts and schemes. "
                "Reject private IP ranges (127.x, 10.x, 192.168.x, 169.254.x)."
            ),
        ))
