"""Comprehensive tests for the shell injection detection rule (CWE-78)."""
import ast
from pathlib import Path

from mcpaudit.rules.shell_injection import check_shell_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

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
    assert len(lines) == 6


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("shell_injection_safe.py")
    findings = check_shell_injection(tree, file_path="shell_injection_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


# ---------------------------------------------------------------------------
# Sink detection — each sink type
# ---------------------------------------------------------------------------

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


def test_subprocess_run_detected() -> None:
    src = """
import subprocess

def handle(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert "subprocess.run()" in findings[0].description


def test_subprocess_popen_detected() -> None:
    src = """
import subprocess

def handle(cmd: str) -> str:
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return proc.communicate()[0]
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_subprocess_call_detected() -> None:
    src = """
import subprocess

def handle(cmd: str) -> int:
    return subprocess.call(cmd, shell=True)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_subprocess_check_call_detected() -> None:
    src = """
import subprocess

def handle(cmd: str) -> None:
    subprocess.check_call(cmd, shell=True)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_subprocess_check_output_detected() -> None:
    src = """
import subprocess

def handle(cmd: str) -> bytes:
    return subprocess.check_output(cmd, shell=True)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def test_taint_through_assignment_detected() -> None:
    src = """
import subprocess

def handle(filename: str) -> str:
    cmd = f"cat {filename}"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_augmented_assignment_detected() -> None:
    src = """
import subprocess

def handle(suffix: str) -> str:
    cmd = "echo "
    cmd += suffix
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_call_return_detected() -> None:
    src = """
import subprocess

def handle(user_input: str) -> str:
    cleaned = sanitize(user_input)
    return subprocess.run(cleaned, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_percent_format_taint_detected() -> None:
    src = """
import subprocess

def handle(filename: str) -> str:
    cmd = "ls %s" % filename
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


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


def test_kwargs_taint_detected() -> None:
    src = """
import subprocess

def handle(**kwargs) -> str:
    return subprocess.run(kwargs["cmd"], shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


def test_annotated_assignment_taint() -> None:
    src = """
import subprocess

def handle(user_input: str) -> str:
    cmd: str = user_input
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Context classification — tool decorator → HIGH
# ---------------------------------------------------------------------------

def test_mcp_tool_decorator_severity_high() -> None:
    src = """
import os

@mcp.tool()
def run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_server_tool_decorator_severity_high() -> None:
    src = """
import os

@server.tool()
def run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_handler_name_severity_high() -> None:
    src = """
import os

def handle_command(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unknown_context_severity_medium() -> None:
    src = """
import os

def run_stuff(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# Context classification — safe contexts → NOT flagged
# ---------------------------------------------------------------------------

def test_click_command_not_flagged() -> None:
    src = """
import os, click

@click.command()
def cli_run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_typer_command_not_flagged() -> None:
    src = """
import os, typer

@typer.command()
def cli_run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_init_method_not_flagged() -> None:
    src = """
import os

class Executor:
    def __init__(self, cmd: str) -> None:
        os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_classmethod_not_flagged() -> None:
    src = """
import os

class Executor:
    @classmethod
    def run(cls, cmd: str) -> None:
        os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_staticmethod_not_flagged() -> None:
    src = """
import os

class Executor:
    @staticmethod
    def run(cmd: str) -> None:
        os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_test_function_not_flagged() -> None:
    src = """
import os

def test_system_call(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_safe_dir_cli_not_flagged() -> None:
    src = """
import os

def run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src), file_path="app/cli/runner.py")
    assert findings == []


def test_safe_dir_utils_not_flagged() -> None:
    src = """
import os

def run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src), file_path="app/utils/exec.py")
    assert findings == []


def test_tool_decorator_overrides_safe_dir() -> None:
    src = """
import os

@mcp.tool()
def run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src), file_path="app/utils/tool.py")
    assert len(findings) == 1
    assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# False-positive prevention
# ---------------------------------------------------------------------------

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


def test_self_not_taint_source() -> None:
    src = """
import subprocess

class Handler:
    def run(self) -> str:
        return subprocess.run(self, shell=True, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_shell_false_not_flagged() -> None:
    src = """
import subprocess

def handle(cmd: str) -> str:
    return subprocess.run(cmd, shell=False, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_no_shell_kwarg_not_flagged() -> None:
    """subprocess.run without shell= keyword is not flagged."""
    src = """
import subprocess

def handle(cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True).stdout
"""
    findings = check_shell_injection(ast.parse(src))
    assert findings == []


def test_async_function_detected() -> None:
    src = """
import os

@mcp.tool()
async def run(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_remediation_present() -> None:
    src = """
import os

def handle(cmd: str) -> None:
    os.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert "subprocess.run()" in findings[0].remediation or "list" in findings[0].remediation


# ---------------------------------------------------------------------------
# Import alias tracking
# ---------------------------------------------------------------------------

def test_import_alias_subprocess_detected() -> None:
    src = """
import subprocess as sp

@mcp.tool()
def run(cmd: str) -> None:
    sp.run(cmd, shell=True)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-78"


def test_import_alias_os_detected() -> None:
    src = """
import os as operating_system

@mcp.tool()
def run(cmd: str) -> None:
    operating_system.system(cmd)
"""
    findings = check_shell_injection(ast.parse(src))
    assert len(findings) == 1
