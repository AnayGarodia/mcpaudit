"""Tests for the path traversal detection rule."""
import ast
from pathlib import Path

from mcpaudit.rules.path_traversal import check_path_traversal

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("path_traversal_vulnerable.py")
    findings = check_path_traversal(tree, file_path="path_traversal_vulnerable.py")

    assert len(findings) == 5, f"Expected 5 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-22"
        assert f.severity == "high"
        assert f.line > 0
        assert f.file_path == "path_traversal_vulnerable.py"


def test_vulnerable_fixture_line_numbers() -> None:
    tree = _parse("path_traversal_vulnerable.py")
    findings = check_path_traversal(tree)
    lines = {f.line for f in findings}
    assert len(lines) == 5


def test_open_builtin_detected() -> None:
    src = """
def handle(filename: str) -> str:
    with open(filename) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "open()" in findings[0].description


def test_pathlib_path_attr_detected() -> None:
    src = """
import pathlib

def handle(user_dir: str) -> pathlib.Path:
    return pathlib.Path(user_dir)
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "CWE-22" == findings[0].cwe_id


def test_os_path_join_non_first_arg_detected() -> None:
    src = """
import os

def handle(subdir: str) -> str:
    return os.path.join("/base", subdir)
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "os.path.join" in findings[0].description


def test_os_path_join_only_first_arg_tainted_not_flagged() -> None:
    src = """
import os

def handle(base: str) -> str:
    return os.path.join(base, "static", "logo.png")
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_taint_through_fstring_detected() -> None:
    src = """
def handle(name: str) -> str:
    path = f"/data/{name}"
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_literal_path_not_flagged() -> None:
    src = """
def handle(name: str) -> str:
    with open("/static/known.txt") as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("path_traversal_safe.py")
    findings = check_path_traversal(tree, file_path="path_traversal_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"
