"""Tests for the unsafe deserialization (CWE-502) rule."""
import ast
from pathlib import Path

from mcpaudit.rules.unsafe_deserialization import check_unsafe_deserialization

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings():
    path = FIXTURES / "unsafe_deserialization_vulnerable.py"
    tree = ast.parse(path.read_text())
    findings = check_unsafe_deserialization(tree, str(path))
    assert len(findings) == 3
    for f in findings:
        assert f.cwe_id == "CWE-502"
        assert f.severity == "high"
        assert f.rule_id == "unsafe_deserialization"
        assert f.line > 0


def test_safe_fixture_has_no_findings():
    path = FIXTURES / "unsafe_deserialization_safe.py"
    tree = ast.parse(path.read_text())
    findings = check_unsafe_deserialization(tree, str(path))
    assert findings == []


# ---------------------------------------------------------------------------
# Inline unit tests
# ---------------------------------------------------------------------------

def _check(src: str) -> list:
    return check_unsafe_deserialization(ast.parse(src), "<test>")


def test_pickle_loads_detected():
    src = """
def handle_tool(data: bytes):
    import pickle
    return pickle.loads(data)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-502"


def test_pickle_load_detected():
    src = """
def handle_tool(data: bytes):
    import pickle
    return pickle.load(data)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_marshal_loads_detected():
    src = """
def handle_tool(data: bytes):
    import marshal
    return marshal.loads(data)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_yaml_load_no_loader_detected():
    src = """
def handle_tool(config: str):
    import yaml
    return yaml.load(config)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_yaml_load_full_loader_detected():
    src = """
def handle_tool(config: str):
    import yaml
    return yaml.load(config, Loader=yaml.FullLoader)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_yaml_safe_load_not_flagged():
    src = """
def handle_tool(config: str):
    import yaml
    return yaml.safe_load(config)
"""
    assert _check(src) == []


def test_yaml_safe_loader_explicit_not_flagged():
    src = """
def handle_tool(config: str):
    import yaml
    return yaml.load(config, Loader=yaml.SafeLoader)
"""
    assert _check(src) == []


def test_yaml_safe_loader_name_not_flagged():
    src = """
from yaml import SafeLoader
def handle_tool(config: str):
    import yaml
    return yaml.load(config, Loader=SafeLoader)
"""
    assert _check(src) == []


def test_pickle_hardcoded_not_flagged():
    src = """
def load_cache():
    import pickle
    with open("/var/cache/state.pkl", "rb") as f:
        return pickle.loads(f.read())
"""
    # Hardcoded path — not tainted from params
    assert _check(src) == []


def test_safe_context_not_flagged():
    src = """
import click

@click.command()
def cli(data: bytes):
    import pickle
    return pickle.loads(data)
"""
    assert _check(src) == []


def test_unknown_context_medium():
    src = """
def some_function(data: bytes):
    import pickle
    return pickle.loads(data)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_tool_context_high():
    src = """
from unittest.mock import MagicMock
mcp = MagicMock()

@mcp.tool()
def deserialize(data: bytes):
    import pickle
    return pickle.loads(data)
"""
    findings = _check(src)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_tainted_via_assignment():
    src = """
def handle_tool(raw: bytes):
    import pickle
    data = raw
    return pickle.loads(data)
"""
    findings = _check(src)
    assert len(findings) == 1


def test_description_mentions_deserializing():
    src = """
def handle_tool(data: bytes):
    import pickle
    return pickle.loads(data)
"""
    findings = _check(src)
    assert "deserializ" in findings[0].description.lower()


def test_rule_id():
    src = """
def handle_tool(data: bytes):
    import pickle
    return pickle.loads(data)
"""
    findings = _check(src)
    assert findings[0].rule_id == "unsafe_deserialization"
