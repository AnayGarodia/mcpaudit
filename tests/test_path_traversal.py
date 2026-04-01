"""Comprehensive tests for the path traversal detection rule (CWE-22)."""
import ast
from pathlib import Path

from mcpaudit.rules.path_traversal import check_path_traversal

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

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


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("path_traversal_safe.py")
    findings = check_path_traversal(tree, file_path="path_traversal_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


# ---------------------------------------------------------------------------
# Sink detection — each sink type must be detected
# ---------------------------------------------------------------------------

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


def test_io_open_detected() -> None:
    src = """
import io

def handle(path: str) -> str:
    with io.open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "io.open()" in findings[0].description


def test_os_open_detected() -> None:
    src = """
import os

def handle(path: str) -> int:
    return os.open(path, os.O_RDONLY)
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "os.open()" in findings[0].description


def test_path_constructor_detected() -> None:
    src = """
from pathlib import Path

def handle(user_path: str) -> Path:
    return Path(user_path)
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_os_path_join_non_first_arg_detected() -> None:
    src = """
import os

def handle(subdir: str) -> str:
    return os.path.join("/base", subdir)
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "os.path.join" in findings[0].description


def test_os_path_join_third_arg_tainted() -> None:
    src = """
import os

def handle(filename: str) -> str:
    return os.path.join("/base", "subdir", filename)
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# os.path.join — only first arg tainted is NOT flagged
# ---------------------------------------------------------------------------

def test_os_path_join_only_first_arg_tainted_not_flagged() -> None:
    src = """
import os

def handle(base: str) -> str:
    return os.path.join(base, "static", "logo.png")
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def test_taint_through_fstring_detected() -> None:
    src = """
def handle(name: str) -> str:
    path = f"/data/{name}"
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_assignment_detected() -> None:
    src = """
def handle(user_path: str) -> str:
    p = user_path
    with open(p) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_concat_detected() -> None:
    src = """
def handle(name: str) -> str:
    path = "/data/" + name
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_call_return_detected() -> None:
    src = """
def handle(user_path: str) -> str:
    cleaned = sanitize(user_path)
    with open(cleaned) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_subscript_detected() -> None:
    src = """
def handle(paths: dict) -> str:
    with open(paths["main"]) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_augmented_assignment() -> None:
    src = """
def handle(suffix: str) -> str:
    path = "/data/"
    path += suffix
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_annotated_assignment() -> None:
    src = """
def handle(user_path: str) -> str:
    p: str = user_path
    with open(p) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Context classification — tool decorator → HIGH
# ---------------------------------------------------------------------------

def test_mcp_tool_decorator_severity_high() -> None:
    src = """
@mcp.tool()
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_server_tool_decorator_severity_high() -> None:
    src = """
@server.tool()
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_bare_tool_decorator_severity_high() -> None:
    src = """
@tool
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_call_tool_decorator_severity_high() -> None:
    src = """
@server.call_tool()
def process(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# Context classification — name heuristics → tool (HIGH) or unknown (MEDIUM)
# ---------------------------------------------------------------------------

def test_handler_name_severity_high() -> None:
    src = """
def handle_file_request(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_execute_name_severity_high() -> None:
    src = """
def execute_read(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unknown_context_severity_medium() -> None:
    src = """
def read_stuff(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# Context classification — safe contexts → NOT flagged
# ---------------------------------------------------------------------------

def test_click_command_not_flagged() -> None:
    src = """
import click

@click.command()
def cli_read(path: str) -> None:
    with open(path) as f:
        print(f.read())
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_typer_command_not_flagged() -> None:
    src = """
import typer

@typer.command()
def cli_read(path: str) -> None:
    with open(path) as f:
        print(f.read())
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_init_method_not_flagged() -> None:
    src = """
class Handler:
    def __init__(self, config_path: str) -> None:
        with open(config_path) as f:
            self.config = f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_post_init_not_flagged() -> None:
    src = """
class Config:
    def __post_init__(self, path: str) -> None:
        with open(path) as f:
            self.data = f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_classmethod_not_flagged() -> None:
    src = """
class Config:
    @classmethod
    def from_file(cls, path: str):
        with open(path) as f:
            return cls(f.read())
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_staticmethod_not_flagged() -> None:
    src = """
class Utils:
    @staticmethod
    def read(path: str) -> str:
        with open(path) as f:
            return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_property_not_flagged() -> None:
    src = """
class Config:
    @property
    def data(self, path: str) -> str:
        with open(path) as f:
            return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_test_function_not_flagged() -> None:
    src = """
def test_read_file(tmp_path) -> None:
    with open(tmp_path / "test.txt") as f:
        assert f.read() == "ok"
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_safe_dir_cli_not_flagged() -> None:
    src = """
def load(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src), file_path="app/cli/loader.py")
    assert findings == []


def test_safe_dir_utils_not_flagged() -> None:
    src = """
def load(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src), file_path="app/utils/files.py")
    assert findings == []


def test_safe_dir_config_not_flagged() -> None:
    src = """
def load(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src), file_path="app/config/loader.py")
    assert findings == []


def test_safe_dir_auth_not_flagged() -> None:
    src = """
def load(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src), file_path="app/auth/keys.py")
    assert findings == []


def test_tool_decorator_overrides_safe_dir() -> None:
    """@mcp.tool in a utils/ directory should still be flagged as HIGH."""
    src = """
@mcp.tool()
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src), file_path="app/utils/file_tool.py")
    assert len(findings) == 1
    assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# False-positive prevention
# ---------------------------------------------------------------------------

def test_literal_path_not_flagged() -> None:
    src = """
def handle(name: str) -> str:
    with open("/static/known.txt") as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_no_args_open_not_flagged() -> None:
    """open() with no arguments should not crash the rule."""
    src = """
def bad_code():
    f = open()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_kwargs_not_flagged() -> None:
    """open(file=literal) with keyword args only."""
    src = """
def handle(mode: str) -> str:
    with open(file="/etc/passwd", mode=mode) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_self_cls_not_tainted() -> None:
    src = """
class Svc:
    def load(self, cls) -> str:
        with open(self.path) as f:
            return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert findings == []


def test_async_function_detected() -> None:
    src = """
@mcp.tool()
async def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_nested_function_separate_context() -> None:
    """Inner function should have its own context classification."""
    src = """
@mcp.tool()
def outer(path: str) -> str:
    def inner(p: str) -> str:
        with open(p) as f:
            return f.read()
    return inner(path)
"""
    findings = check_path_traversal(ast.parse(src))
    # outer has open(path) via the call (not direct), inner is "unknown" context
    # The open(p) in inner is unknown context → medium
    assert any(f.severity == "medium" for f in findings)


def test_multiple_sinks_in_one_function() -> None:
    src = """
import os

@mcp.tool()
def multi(a: str, b: str) -> str:
    with open(a) as f:
        data = f.read()
    path = os.path.join("/base", b)
    return data + path
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 2


def test_remediation_present() -> None:
    src = """
def handle(path: str) -> str:
    with open(path) as f:
        return f.read()
"""
    findings = check_path_traversal(ast.parse(src))
    assert len(findings) == 1
    assert "resolve()" in findings[0].remediation
