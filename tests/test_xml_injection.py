"""Comprehensive tests for the XML injection detection rule (CWE-611)."""
import ast
from pathlib import Path

from mcpaudit.rules.xml_injection import check_xml_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("xml_injection_vulnerable.py")
    findings = check_xml_injection(tree, file_path="xml_injection_vulnerable.py")

    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-611"
        assert f.severity == "high"
        assert f.line > 0
        assert f.file_path == "xml_injection_vulnerable.py"


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("xml_injection_safe.py")
    findings = check_xml_injection(tree, file_path="xml_injection_safe.py")
    assert findings == [], f"Unexpected findings: {findings}"


# ---------------------------------------------------------------------------
# Sink detection
# ---------------------------------------------------------------------------

def test_stdlib_alias_detected() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert "xml.etree.ElementTree.fromstring()" in findings[0].description


def test_lxml_etree_detected() -> None:
    src = """
from lxml import etree

@mcp.tool()
def parse(data: str):
    return etree.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert "etree.fromstring()" in findings[0].description


def test_imported_fromstring_detected() -> None:
    src = """
from xml.etree.ElementTree import fromstring

@mcp.tool()
def parse(data: str):
    return fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert "fromstring()" in findings[0].description


def test_xml_alias_func_detected() -> None:
    """XML() is an alias for fromstring in stdlib."""
    src = """
from xml.etree.ElementTree import XML

@mcp.tool()
def parse(data: str):
    return XML(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1


def test_lxml_import_alias_detected() -> None:
    """from lxml import etree as lx — still detected."""
    src = """
from lxml import etree as lx

@mcp.tool()
def parse(data: str):
    return lx.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1


def test_xml_elementtree_module_detected() -> None:
    """from xml.etree import ElementTree → ElementTree.fromstring() detected."""
    src = """
from xml.etree import ElementTree

@mcp.tool()
def parse(data: str):
    return ElementTree.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def test_taint_through_assignment_detected() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(xml_data: str):
    content = xml_data
    return ET.fromstring(content)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_fstring_detected() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(body: str):
    wrapped = f"<root>{body}</root>"
    return ET.fromstring(wrapped)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Safe patterns — not flagged
# ---------------------------------------------------------------------------

def test_defusedxml_not_flagged() -> None:
    src = """
import defusedxml.ElementTree as ET

@mcp.tool()
def parse(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert findings == []


def test_static_xml_not_flagged() -> None:
    src = """
import xml.etree.ElementTree as ET

STATIC = "<root><item>1</item></root>"

@mcp.tool()
def parse(name: str):
    return ET.fromstring(STATIC)
"""
    findings = check_xml_injection(ast.parse(src))
    assert findings == []


def test_string_literal_not_flagged() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(name: str):
    return ET.fromstring("<root/>")
"""
    findings = check_xml_injection(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Context classification
# ---------------------------------------------------------------------------

def test_tool_decorator_severity_high() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unknown_context_severity_medium() -> None:
    src = """
import xml.etree.ElementTree as ET

def parse_something(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_safe_context_not_flagged() -> None:
    src = """
import xml.etree.ElementTree as ET

@classmethod
def parse(cls, data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert findings == []


def test_test_function_not_flagged() -> None:
    src = """
import xml.etree.ElementTree as ET

def test_parse_xml(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------

def test_rule_id_and_cwe() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].rule_id == "xml_injection"
    assert findings[0].cwe_id == "CWE-611"


def test_remediation_mentions_defusedxml() -> None:
    src = """
import xml.etree.ElementTree as ET

@mcp.tool()
def parse(data: str):
    return ET.fromstring(data)
"""
    findings = check_xml_injection(ast.parse(src))
    assert len(findings) == 1
    assert "defusedxml" in findings[0].remediation
