"""Tests for the shell injection detection rule."""
import ast
from pathlib import Path

import pytest

from mcpaudit.rules.shell_injection import check_shell_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("shell_injection_vulnerable.py")
    findings = check_shell_injection(tree, file_path="shell_injection_vulnerable.py")

    assert len(findings) == 6, f"Expected 6 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-78"
        assert f.severity == "high"
        assert f.line > 0
        assert f.file_path == "shell_injection_vulnerable.py"


def test_vulnerable_fixture_line_numbers() -> None:
    tree = _parse("shell_injection_vulnerable.py")
    findings = check_shell_injection(tree)
    lines = {f.line for f in findings}
    # Each of the six dangerous calls must be on a distinct line
    assert len(lines) == 6


def test_os_system_detected() -> None:
    src = """
import os

def handle(user_input: str) -> None:
    os.system(user_input)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-78"
    assert "os.system" in findings[0].description


def test_os_popen_detected() -> None:
    src = """
import os

def handle(user_input: str) -> None:
    os.popen(user_input)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert "os.popen" in findings[0].description


def test_taint_through_assignment_detected() -> None:
    src = """
import subprocess

def handle(filename: str) -> str:
    cmd = f"cat {filename}"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"


def test_taint_through_augmented_assignment_detected() -> None:
    src = """
import subprocess

def handle(suffix: str) -> str:
    cmd = "echo "
    cmd += suffix
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"


def test_taint_through_call_return_detected() -> None:
    src = """
import subprocess

def handle(user_input: str) -> str:
    cleaned = sanitize(user_input)
    return subprocess.run(cleaned, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"


def test_percent_format_taint_detected() -> None:
    src = """
import subprocess

def handle(filename: str) -> str:
    cmd = "ls %s" % filename
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"


def test_ternary_taint_detected() -> None:
    src = """
import subprocess

def handle(user_cmd: str, flag: bool) -> str:
    cmd = user_cmd if flag else "safe"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_varargs_taint_detected() -> None:
    src = """
import subprocess

def handle(*args) -> str:
    return subprocess.run(args[0], shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_self_not_taint_source() -> None:
    src = """
import subprocess

class Handler:
    def run(self) -> str:
        return subprocess.run(self, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == [], f"self should not be a taint source: {findings}"


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("shell_injection_safe.py")
    findings = check_shell_injection(tree, file_path="shell_injection_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


def test_subprocess_without_shell_true_not_flagged() -> None:
    src = """
import subprocess

def handle(filename: str) -> str:
    return subprocess.run(["ls", filename], capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_untainted_arg_not_flagged() -> None:
    src = """
import subprocess

def handle(filename: str) -> str:
    return subprocess.run("ls -la", shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []
