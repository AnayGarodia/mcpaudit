"""Comprehensive tests for the template injection detection rule (CWE-94)."""
import ast
from pathlib import Path

from mcpaudit.rules.template_injection import check_template_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("template_injection_vulnerable.py")
    findings = check_template_injection(tree, file_path="template_injection_vulnerable.py")

    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-94"
        assert f.severity == "high"
        assert f.line > 0
        assert f.file_path == "template_injection_vulnerable.py"


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("template_injection_safe.py")
    findings = check_template_injection(tree, file_path="template_injection_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


# ---------------------------------------------------------------------------
# Sink detection
# ---------------------------------------------------------------------------

def test_jinja2_template_direct_detected() -> None:
    src = """
import jinja2

@mcp.tool()
def render(user_tmpl: str) -> str:
    return jinja2.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert "jinja2.Template()" in findings[0].description


def test_from_string_detected() -> None:
    src = """
import jinja2

@mcp.tool()
def render(user_tmpl: str) -> str:
    env = jinja2.Environment()
    return env.from_string(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert "from_string" in findings[0].description


def test_imported_template_detected() -> None:
    src = """
from jinja2 import Template

@mcp.tool()
def render(user_tmpl: str) -> str:
    return Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert "Template()" in findings[0].description


def test_aliased_template_detected() -> None:
    """from jinja2 import Template as J2Template — still detected."""
    src = """
from jinja2 import Template as J2Template

@mcp.tool()
def render(user_tmpl: str) -> str:
    return J2Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1


def test_mako_template_detected() -> None:
    src = """
import mako

@mcp.tool()
def render(user_tmpl: str) -> str:
    return mako.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def test_taint_through_assignment_detected() -> None:
    src = """
import jinja2

@mcp.tool()
def render(user_tmpl: str) -> str:
    t = user_tmpl
    return jinja2.Template(t).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_fstring_detected() -> None:
    src = """
import jinja2

@mcp.tool()
def render(header: str, body: str) -> str:
    tmpl_str = f"<h1>{header}</h1>{body}"
    return jinja2.Template(tmpl_str).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Safe patterns — not flagged
# ---------------------------------------------------------------------------

def test_static_template_string_not_flagged() -> None:
    src = """
import jinja2

@mcp.tool()
def render(name: str) -> str:
    tmpl = jinja2.Template("Hello, {{ name }}!")
    return tmpl.render(name=name)
"""
    findings = check_template_injection(ast.parse(src))
    assert findings == []


def test_get_template_not_flagged() -> None:
    src = """
import jinja2

env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates/"))

@mcp.tool()
def render(template_name: str) -> str:
    tmpl = env.get_template("report.html")
    return tmpl.render(query=template_name)
"""
    findings = check_template_injection(ast.parse(src))
    assert findings == []


def test_render_with_context_not_flagged() -> None:
    """Calling .render(user_data=x) is safe — user input as context, not template."""
    src = """
import jinja2

@mcp.tool()
def render(user_data: str) -> str:
    tmpl = jinja2.Template("Data: {{ user_data }}")
    return tmpl.render(user_data=user_data)
"""
    findings = check_template_injection(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Context classification
# ---------------------------------------------------------------------------

def test_tool_decorator_severity_high() -> None:
    src = """
import jinja2

@mcp.tool()
def render(user_tmpl: str) -> str:
    return jinja2.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unknown_context_severity_medium() -> None:
    src = """
import jinja2

def render_something(user_tmpl: str) -> str:
    return jinja2.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_safe_context_not_flagged() -> None:
    src = """
import jinja2

@classmethod
def render(cls, user_tmpl: str) -> str:
    return jinja2.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert findings == []


def test_test_function_not_flagged() -> None:
    src = """
import jinja2

def test_template_render(user_tmpl: str) -> None:
    tmpl = jinja2.Template(user_tmpl)
    assert tmpl.render() == ""
"""
    findings = check_template_injection(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------

def test_rule_id_correct() -> None:
    src = """
import jinja2

@mcp.tool()
def render(user_tmpl: str) -> str:
    return jinja2.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].rule_id == "template_injection"
    assert findings[0].cwe_id == "CWE-94"


def test_remediation_present() -> None:
    src = """
import jinja2

@mcp.tool()
def render(user_tmpl: str) -> str:
    return jinja2.Template(user_tmpl).render()
"""
    findings = check_template_injection(ast.parse(src))
    assert len(findings) == 1
    assert "get_template" in findings[0].remediation
