"""
Rule: Unsafe Deserialization (CWE-502)

Detects user-controlled input flowing into deserialization functions that can
execute arbitrary code or produce unexpected objects when given malicious data.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, utils, etc.).

Dangerous sinks:
  - pickle.loads(tainted)        — arbitrary code execution
  - pickle.load(tainted)         — arbitrary code execution (file object)
  - marshal.loads(tainted)       — arbitrary code execution
  - yaml.load(tainted)           — code execution if Loader is not SafeLoader
    (yaml.safe_load is NOT flagged — it uses SafeLoader by default)

For yaml.load specifically: only flagged when the Loader= keyword argument is
absent OR is not yaml.SafeLoader / yaml.CSafeLoader / yaml.BaseLoader.
yaml.safe_load() is never flagged.

Alias imports (e.g. `import pickle as pk`) are tracked via TaintVisitor._resolve_module.
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

_PICKLE_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("pickle", "loads"),
    ("pickle", "load"),
    ("marshal", "loads"),
})

_YAML_LOAD_PAIR: tuple[str, str] = ("yaml", "load")

# Loader= values that make yaml.load safe.
_SAFE_YAML_LOADERS: frozenset[str] = frozenset({
    "SafeLoader", "CSafeLoader", "BaseLoader",
})


def check_unsafe_deserialization(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches an unsafe deserializer."""
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
            if pair in _PICKLE_SINKS and node.args and self._is_tainted(node.args[0]):
                self._report(node, f"{pair[0]}.{pair[1]}()", pair[0])
            elif pair == _YAML_LOAD_PAIR and node.args and self._is_tainted(node.args[0]):
                if not self._yaml_has_safe_loader(node):
                    self._report(
                        node,
                        "yaml.load()",
                        "yaml",
                        extra=(
                            "Pass Loader=yaml.SafeLoader (or use yaml.safe_load()) "
                            "to prevent arbitrary object instantiation."
                        ),
                    )
        self.generic_visit(node)

    def _report(
        self,
        node: ast.Call,
        label: str,
        lib: str,
        extra: str | None = None,
    ) -> None:
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        if extra is None:
            remediation = (
                f"Do not deserialize untrusted data with {lib}. "
                "Use a safe data format (JSON, MessagePack) or validate the "
                "serialized payload against a strict schema before loading."
            )
        else:
            remediation = extra
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-502",
            rule_id="unsafe_deserialization",
            description=(
                f"User-controlled input passed to {label}; "
                "deserializing untrusted data can lead to arbitrary code execution."
            ),
            remediation=remediation,
        ))

    @staticmethod
    def _yaml_has_safe_loader(node: ast.Call) -> bool:
        """Return True if yaml.load() has a Loader= keyword that is a safe loader."""
        for kw in node.keywords:
            if kw.arg == "Loader":
                val = kw.value
                # yaml.SafeLoader → ast.Attribute
                if isinstance(val, ast.Attribute) and val.attr in _SAFE_YAML_LOADERS:
                    return True
                # SafeLoader (bare name import) → ast.Name
                if isinstance(val, ast.Name) and val.id in _SAFE_YAML_LOADERS:
                    return True
        return False
