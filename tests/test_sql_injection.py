"""Tests for the SQL injection (CWE-89) rule."""
import ast
from pathlib import Path

from mcpaudit.rules.sql_injection import check_sql_injection

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings():
    path = FIXTURES / "sql_injection_vulnerable.py"
    tree = ast.parse(path.read_text())
    findings = check_sql_injection(tree, str(path))
    assert len(findings) == 3
    for f in findings:
        assert f.cwe_id == "CWE-89"
        assert f.severity == "high"
        assert f.rule_id == "sql_injection"
        assert f.line > 0


def test_safe_fixture_has_no_findings():
    path = FIXTURES / "sql_injection_safe.py"
    tree = ast.parse(path.read_text())
    findings = check_sql_injection(tree, str(path))
    assert findings == []


# ---------------------------------------------------------------------------
# Inline unit tests
# ---------------------------------------------------------------------------

def _check(src: str) -> list:
    return check_sql_injection(ast.parse(src), "<test>")


def test_fstring_query_detected():
    src = """
def handle_tool(name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-89"


def test_concatenated_query_detected():
    src = """
def handle_tool(table: str):
    db.execute("SELECT * FROM " + table)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_parameterized_query_not_flagged():
    src = """
def handle_tool(name: str):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
"""
    assert _check(src) == []


def test_static_query_not_flagged():
    src = """
def fetch_all():
    cursor.execute("SELECT * FROM users")
"""
    assert _check(src) == []


def test_safe_context_not_flagged():
    src = """
import click

@click.command()
def cli(name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""
    assert _check(src) == []


def test_unknown_context_medium():
    src = """
def some_function(val: str):
    db.execute("DELETE FROM t WHERE id = " + val)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_tool_context_high():
    src = """
from unittest.mock import MagicMock
mcp = MagicMock()

@mcp.tool()
def query(val: str):
    cursor.execute("SELECT * FROM t WHERE x = " + val)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_tainted_variable_detected():
    src = """
def handle_tool(user_id: str):
    sql = "SELECT * FROM users WHERE id = " + user_id
    db.execute(sql)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_description_mentions_execute():
    src = """
def handle_tool(q: str):
    cursor.execute(f"SELECT {q}")
"""
    findings = _check(src)
    assert "execute" in findings[0].description


def test_remediation_mentions_parameterized():
    src = """
def handle_tool(q: str):
    cursor.execute(f"SELECT {q}")
"""
    findings = _check(src)
    assert "parameterized" in findings[0].remediation.lower()


def test_rule_id():
    src = """
def handle_tool(q: str):
    cursor.execute(f"SELECT {q}")
"""
    findings = _check(src)
    assert findings[0].rule_id == "sql_injection"
