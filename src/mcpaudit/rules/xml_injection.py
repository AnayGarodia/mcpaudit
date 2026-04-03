"""
Rule: XML External Entity Injection (CWE-611)

Detects user-controlled XML content being parsed by stdlib or lxml XML parsers,
which can expose the server to XXE attacks — reading local files, SSRF,
or denial of service via entity expansion (billion laughs).

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, auth, etc.).

Dangerous sinks:
  - xml.etree.ElementTree.fromstring(tainted)
  - xml.etree.ElementTree.XML(tainted)        — stdlib alias for fromstring
  - lxml.etree.fromstring(tainted)
  - ET.fromstring(tainted)  where import xml.etree.ElementTree as ET
  - etree.fromstring(tainted) where from lxml import etree
  - fromstring(tainted)     where from xml.etree.ElementTree import fromstring

Safe patterns (NOT flagged):
  - defusedxml.ElementTree.fromstring(tainted)  — uses hardened parser
  - ET.fromstring("static string")              — untainted input
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# Full module paths considered vulnerable XML parsers.
_VULNERABLE_XML_MODULES: frozenset[str] = frozenset({
    "xml.etree.ElementTree",
    "lxml.etree",
})

# Function names within those modules that parse raw XML content.
_XML_PARSE_FUNC_NAMES: frozenset[str] = frozenset({
    "fromstring",
    "XML",  # stdlib alias for fromstring
})


def check_xml_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled XML content reaches an unsafe parser."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Local names bound to a vulnerable XML module (e.g. ET, etree).
        self._xml_module_names: set[str] = set()
        # Local names bound to a vulnerable parse function (e.g. fromstring).
        self._xml_func_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Track `import xml.etree.ElementTree as ET` style aliases."""
        super().visit_Import(node)
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name
            if alias.name in _VULNERABLE_XML_MODULES:
                self._xml_module_names.add(bound)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track `from lxml import etree` and `from xml.etree.ElementTree import fromstring`."""
        super().visit_ImportFrom(node)
        module = node.module or ""
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name
            full = f"{module}.{alias.name}" if module else alias.name
            # from xml.etree import ElementTree → full = "xml.etree.ElementTree"
            # from lxml import etree → full = "lxml.etree"
            if full in _VULNERABLE_XML_MODULES:
                self._xml_module_names.add(bound)
            # from xml.etree.ElementTree import fromstring
            if module in _VULNERABLE_XML_MODULES and alias.name in _XML_PARSE_FUNC_NAMES:
                self._xml_func_names.add(bound)

    def visit_Call(self, node: ast.Call) -> None:
        pair = self._resolved_attr_pair(node)
        if pair is not None:
            mod, func = pair
            if func in _XML_PARSE_FUNC_NAMES:
                # Pattern 1a: alias-resolved module — import xml.etree.ElementTree as ET
                # → _resolve_module("ET") = "xml.etree.ElementTree"
                if mod in _VULNERABLE_XML_MODULES:
                    if node.args and self._is_tainted(node.args[0]):
                        self._report(node, f"{mod}.{func}()")
                # Pattern 1b: module name tracked via visit_ImportFrom (non-aliased)
                # → `from lxml import etree` → etree in _xml_module_names
                elif mod in self._xml_module_names:
                    if node.args and self._is_tainted(node.args[0]):
                        self._report(node, f"{mod}.{func}()")

        # Pattern 2: bare function call — from xml.etree.ElementTree import fromstring
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self._xml_func_names
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
            cwe_id="CWE-611",
            rule_id="xml_injection",
            description=(
                f"User-controlled data passed to {label}; "
                "an attacker can supply malicious XML to trigger XXE attacks — "
                "reading local files, performing SSRF, or causing denial of service "
                "via entity expansion."
            ),
            remediation=(
                "Use defusedxml instead of the standard library or lxml: "
                "`import defusedxml.ElementTree as ET`. "
                "If lxml is required, disable entity resolution with: "
                "`lxml.etree.XMLParser(resolve_entities=False, no_network=True)`."
            ),
        ))
