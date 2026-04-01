"""Tests for the code injection (CWE-95) rule."""
import ast
from pathlib import Path

import pytest

from mcpaudit.rules.code_injection import check_code_injection

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings():
    path = FIXTURES / "code_injection_vulnerable.py"
    tree = ast.parse(path.read_text())
    findings = check_code_injection(tree, str(path))
    assert len(findings) == 3
    for f in findings:
        assert f.cwe_id == "CWE-95"
        assert f.severity == "high"
        assert f.rule_id == "code_injection"
        assert f.line > 0


def test_vulnerable_fixture_distinct_lines():
    path = FIXTURES / "code_injection_vulnerable.py"
    tree = ast.parse(path.read_text())
    findings = check_code_injection(tree, str(path))
    lines = [f.line for f in findings]
    assert len(set(lines)) == len(lines), "Expected distinct line numbers"


def test_safe_fixture_has_no_findings():
    path = FIXTURES / "code_injection_safe.py"
    tree = ast.parse(path.read_text())
    findings = check_code_injection(tree, str(path))
    assert findings == []


# ---------------------------------------------------------------------------
# Inline unit tests
# ---------------------------------------------------------------------------

def _check(src: str) -> list:
    return check_code_injection(ast.parse(src), "<test>")


def test_eval_tainted_direct():
    src = """
def handle_tool(code: str):
    return eval(code)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-95"


def test_exec_tainted_direct():
    src = """
def handle_tool(code: str):
    exec(code)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_eval_hardcoded_not_flagged():
    src = """
def compute():
    return eval("1 + 2")
"""
    assert _check(src) == []


def test_exec_hardcoded_not_flagged():
    src = """
def compute():
    exec("x = 1")
"""
    assert _check(src) == []


def test_eval_tainted_fstring():
    src = """
def handle_tool(expr: str):
    result = eval(f"({expr})")
    return result
"""
    findings = _check(src)
    assert len(findings) == 1


def test_eval_safe_context_not_flagged():
    src = """
import click

@click.command()
def cli_command(code: str):
    eval(code)
"""
    assert _check(src) == []


def test_eval_unknown_context_medium():
    src = """
def some_function(code: str):
    eval(code)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_eval_tool_context_high():
    src = """
from unittest.mock import MagicMock
mcp = MagicMock()

@mcp.tool()
def run_expr(code: str):
    eval(code)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_description_mentions_eval():
    src = """
def run(code: str):
    eval(code)
"""
    findings = _check(src)
    assert "eval" in findings[0].description


def test_remediation_mentions_literal_eval():
    src = """
def run(code: str):
    eval(code)
"""
    findings = _check(src)
    assert "literal_eval" in findings[0].remediation


def test_tainted_via_assignment():
    src = """
def handle_tool(user_input: str):
    expr = user_input + " + 1"
    eval(expr)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_rule_id():
    src = """
def handle_tool(code: str):
    exec(code)
"""
    findings = _check(src)
    assert findings[0].rule_id == "code_injection"
