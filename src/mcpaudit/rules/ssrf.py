"""
Rule: Server-Side Request Forgery (CWE-918)

Detects user-controlled input flowing into HTTP request functions as the URL
argument, allowing an attacker to make the server issue requests to arbitrary
internal or external hosts.

Taint sources: function parameters (excluding self/cls, including *args/**kwargs)
and local variables assigned from tainted expressions.

Dangerous sinks:
  - requests.get/post/put/delete/patch/head/request(url, ...)
  - httpx.get/post/put/delete/patch/head/request(url, ...)
  - urllib.request.urlopen(url, ...)

The URL may be passed positionally (first arg) or as the `url=` keyword.

Limitations: session-based calls like `requests.Session().get(url)` are not
caught — the chained call's inner value is not a simple ast.Name.
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

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

    def visit_Call(self, node: ast.Call) -> None:
        pair = self._attr_pair(node)
        if pair is not None and pair in _HTTP_SINKS:
            self._check_url_arg(node, f"{pair[0]}.{pair[1]}()")

        triple = self._attr_triple(node)
        if triple is not None and triple in _TRIPLE_SINKS:
            self._check_url_arg(node, "urllib.request.urlopen()")

        self.generic_visit(node)

    def _check_url_arg(self, node: ast.Call, label: str) -> None:
        """Flag when the URL argument (positional or url= keyword) is tainted."""
        if node.args and self._is_tainted(node.args[0]):
            self._report(node, label)
            return
        # Check for url= keyword when not passed positionally.
        if not node.args:
            for kw in node.keywords:
                if kw.arg == "url" and self._is_tainted(kw.value):
                    self._report(node, label)
                    return

    def _report(self, node: ast.Call, label: str) -> None:
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity="high",
            cwe_id="CWE-918",
            description=(
                f"User-controlled input passed as the URL to {label}; "
                "an attacker can redirect the request to internal services or arbitrary hosts."
            ),
            remediation=(
                "Validate the URL against an allowlist of permitted hosts and schemes. "
                "Reject private IP ranges (127.x, 10.x, 192.168.x, 169.254.x)."
            ),
        ))
