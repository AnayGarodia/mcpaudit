"""
Rule: Hardcoded Secrets (CWE-798)

Detects credentials and API keys embedded as string literals in source code.

Two detection modes:
  1. Variable name matching — assignment targets whose names suggest a secret
     (e.g. password, api_key, token) whose value is a non-placeholder string literal.
  2. Known key format regexes — string literals whose content matches the pattern
     of real API keys (AWS, OpenAI, GitHub) regardless of variable name.

Limitations: f-string values, environment variable lookups, and tuple-unpacking
targets are not analysed.
"""
import ast
import re

from mcpaudit.models import Finding

_SECRET_NAMES: frozenset[str] = frozenset({
    "password", "passwd", "api_key", "apikey", "secret", "token",
    "auth_token", "private_key", "secret_key", "access_key", "client_secret",
})

_PLACEHOLDERS: frozenset[str] = frozenset({
    "", "changeme", "xxx", "placeholder", "secret", "password", "token",
    "your_token", "your_api_key", "your_secret", "test", "testing",
})

# Substrings in a value that indicate it is a dummy/placeholder, not a real secret.
_PLACEHOLDER_SUBSTRINGS: tuple[str, ...] = (
    "your_", "dummy", "fake", "example", "placeholder", "changeme", "fixme",
    "todo", "replace_me", "insert_",
)

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),           # AWS access key ID
    re.compile(r"sk-[A-Za-z0-9]{48}"),          # OpenAI API key
    re.compile(r"gh[ps]_[A-Za-z0-9]{36}"),      # GitHub personal/server access token
]


def check_hardcoded_secrets(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where a secret credential is assigned as a string literal."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Tracks (lineno, value) pairs already reported to prevent duplicates
        # from multi-target assignments like `a = b = "AKIA..."`.
        self._reported: set[tuple[int, str]] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_assignment(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            self._check_assignment(node.target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _check_assignment(self, name: str, value_node: ast.expr, lineno: int) -> None:
        if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
            return
        val: str = value_node.value

        # Mode 2: regex patterns fire regardless of variable name.
        for pattern in _SECRET_PATTERNS:
            if pattern.search(val):
                self._report(name, val, lineno, "matches a known API key format")
                return

        # Mode 1: variable name suggests a secret.
        if name.lower() not in _SECRET_NAMES:
            return
        if self._is_placeholder(val):
            return
        self._report(name, val, lineno, "variable name suggests a secret credential")

    def _report(self, name: str, val: str, lineno: int, reason: str) -> None:
        key = (lineno, val)
        if key in self._reported:
            return
        self._reported.add(key)
        preview = val[:6] + "..." if len(val) > 6 else val
        self.findings.append(Finding(
            file_path=self.file_path,
            line=lineno,
            severity="high",
            cwe_id="CWE-798",
            rule_id="hardcoded_secrets",
            description=(
                f"Hardcoded secret in '{name}' ({reason}); "
                f"value starts with {preview!r}."
            ),
            remediation=(
                "Store secrets in environment variables or a secrets manager "
                "(e.g. os.environ['KEY']). Never commit credentials to source control."
            ),
        ))

    @staticmethod
    def _is_placeholder(val: str) -> bool:
        lower = val.lower()
        if lower in _PLACEHOLDERS:
            return True
        if lower.startswith("<") and lower.endswith(">"):
            return True
        if any(sub in lower for sub in _PLACEHOLDER_SUBSTRINGS):
            return True
        return False
