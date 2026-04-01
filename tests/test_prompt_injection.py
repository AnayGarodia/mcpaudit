"""Tests for the targeted prompt injection detection rule."""
import ast
from pathlib import Path

from mcpaudit.rules.prompt_injection import check_prompt_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("prompt_injection_vulnerable.py")
    findings = check_prompt_injection(tree, file_path="prompt_injection_vulnerable.py")

    assert len(findings) == 5, f"Expected 5 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-020"
        assert f.severity == "medium"
        assert f.line > 0
        assert f.file_path == "prompt_injection_vulnerable.py"


def test_vulnerable_fixture_line_numbers() -> None:
    tree = _parse("prompt_injection_vulnerable.py")
    findings = check_prompt_injection(tree)
    lines = {f.line for f in findings}
    assert len(lines) == 5, f"Expected 5 distinct lines, got {lines}"


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("prompt_injection_safe.py")
    findings = check_prompt_injection(tree, file_path="prompt_injection_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


# ---------------------------------------------------------------------------
# Pattern 1: External data passthrough — should be flagged
# ---------------------------------------------------------------------------

def test_http_fetch_direct_return_detected() -> None:
    src = """
import requests

def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1
    assert "external content" in findings[0].description


def test_http_fetch_via_variable_detected() -> None:
    src = """
import requests

def fetch(url: str) -> str:
    response = requests.get(url)
    return response.text
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1


def test_file_read_detected() -> None:
    src = """
def read(path: str) -> str:
    return open(path).read()
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1


def test_subprocess_output_detected() -> None:
    src = """
import subprocess

def run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True).decode()
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1


def test_fetch_with_hardcoded_url_not_flagged() -> None:
    """No user-controlled fetch target — safe."""
    src = """
import requests

def get_status() -> str:
    return requests.get("https://api.example.com/status").text
"""
    findings = check_prompt_injection(ast.parse(src))
    assert findings == [], f"Hardcoded URL should not be flagged: {findings}"


# ---------------------------------------------------------------------------
# Pattern 2: Instruction string injection — should be flagged
# ---------------------------------------------------------------------------

def test_instruction_fstring_you_are_detected() -> None:
    src = """
def set_persona(role: str) -> str:
    return f"You are {role}. Always act as {role}."
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1
    assert "instruction-like keywords" in findings[0].description


def test_instruction_fstring_system_detected() -> None:
    src = """
def inject(instructions: str) -> str:
    return f"System: {instructions}"
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1


def test_instruction_via_variable_detected() -> None:
    src = """
def build(instructions: str) -> str:
    msg = f"System: {instructions}\\nAssistant: understood."
    return msg
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1


def test_instruction_concat_detected() -> None:
    src = """
def inject(role: str) -> str:
    return "You are " + role + ". Act as instructed."
"""
    findings = check_prompt_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# False-positive cases — should NOT be flagged
# ---------------------------------------------------------------------------

def test_simple_echo_not_flagged() -> None:
    src = """
def greet(name: str) -> str:
    return f"Hello, {name}! How can I help?"
"""
    findings = check_prompt_injection(ast.parse(src))
    assert findings == [], f"Simple echo should not be flagged: {findings}"


def test_computation_result_not_flagged() -> None:
    src = """
def count(text: str) -> str:
    n = len(text.split())
    return f"Word count: {n}"
"""
    findings = check_prompt_injection(ast.parse(src))
    assert findings == [], f"Computation result should not be flagged: {findings}"


def test_error_message_not_flagged() -> None:
    src = """
def validate(user_input: str) -> str:
    return f"Error: '{user_input}' is not valid."
"""
    findings = check_prompt_injection(ast.parse(src))
    assert findings == [], f"Error message should not be flagged: {findings}"


def test_mcp_tool_normal_pattern_not_flagged() -> None:
    """Standard MCP tool: takes param, does work, returns result label."""
    src = """
def search(query: str) -> str:
    results = do_search(query)
    return f"Results for '{query}': {len(results)} items found."
"""
    findings = check_prompt_injection(ast.parse(src))
    assert findings == [], f"Normal MCP tool pattern should not be flagged: {findings}"
