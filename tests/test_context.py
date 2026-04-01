"""Tests for the TaintVisitor context classification system."""
import ast

from mcpaudit.rules._taint import TaintVisitor


def _classify(src: str, file_path: str = "") -> list[str]:
    """Parse source and return the context classification of each function."""
    tree = ast.parse(src)
    visitor = _ContextCollector(file_path)
    visitor.visit(tree)
    return visitor.contexts


class _ContextCollector(TaintVisitor):
    """Visitor that collects context classifications for testing."""

    def __init__(self, file_path: str = "") -> None:
        super().__init__()
        self.file_path = file_path
        self.contexts: list[str] = []

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        ctx = self._classify_function(node)
        self.contexts.append(ctx)
        super()._visit_function(node)


# ---------------------------------------------------------------------------
# Decorator-based classification
# ---------------------------------------------------------------------------

def test_bare_tool_decorator() -> None:
    src = "@tool\ndef f(x): pass"
    assert _classify(src) == ["tool"]


def test_mcp_tool_decorator() -> None:
    src = "@mcp.tool()\ndef f(x): pass"
    assert _classify(src) == ["tool"]


def test_server_tool_decorator() -> None:
    src = "@server.tool()\ndef f(x): pass"
    assert _classify(src) == ["tool"]


def test_call_tool_decorator() -> None:
    src = "@server.call_tool()\ndef f(x): pass"
    assert _classify(src) == ["tool"]


def test_click_command_safe() -> None:
    src = "@click.command()\ndef f(x): pass"
    assert _classify(src) == ["safe"]


def test_typer_command_safe() -> None:
    src = "@typer.command()\ndef f(x): pass"
    assert _classify(src) == ["safe"]


def test_group_decorator_safe() -> None:
    src = "@app.group()\ndef f(x): pass"
    assert _classify(src) == ["safe"]


def test_classmethod_safe() -> None:
    src = "class C:\n  @classmethod\n  def f(cls): pass"
    assert _classify(src) == ["safe"]


def test_staticmethod_safe() -> None:
    src = "class C:\n  @staticmethod\n  def f(): pass"
    assert _classify(src) == ["safe"]


def test_property_safe() -> None:
    src = "class C:\n  @property\n  def f(self): pass"
    assert _classify(src) == ["safe"]


# ---------------------------------------------------------------------------
# Name-based classification
# ---------------------------------------------------------------------------

def test_dunder_init_safe() -> None:
    src = "class C:\n  def __init__(self): pass"
    assert _classify(src) == ["safe"]


def test_dunder_new_safe() -> None:
    src = "class C:\n  def __new__(cls): pass"
    assert _classify(src) == ["safe"]


def test_dunder_post_init_safe() -> None:
    src = "class C:\n  def __post_init__(self): pass"
    assert _classify(src) == ["safe"]


def test_test_prefix_safe() -> None:
    src = "def test_something(): pass"
    assert _classify(src) == ["safe"]


def test_handler_name_tool() -> None:
    src = "def handle_request(x): pass"
    assert _classify(src) == ["tool"]


def test_execute_name_tool() -> None:
    src = "def execute_command(x): pass"
    assert _classify(src) == ["tool"]


def test_tool_in_name() -> None:
    src = "def my_tool_function(x): pass"
    assert _classify(src) == ["tool"]


def test_plain_function_unknown() -> None:
    src = "def process_data(x): pass"
    assert _classify(src) == ["unknown"]


# ---------------------------------------------------------------------------
# File path classification
# ---------------------------------------------------------------------------

def test_cli_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/cli/main.py") == ["safe"]


def test_commands_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/commands/deploy.py") == ["safe"]


def test_config_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/config/settings.py") == ["safe"]


def test_utils_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/utils/helpers.py") == ["safe"]


def test_utilities_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/utilities/helpers.py") == ["safe"]


def test_auth_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="server/auth/oauth.py") == ["safe"]


def test_middleware_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="server/middleware/rate_limit.py") == ["safe"]


def test_models_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/models/user.py") == ["safe"]


def test_providers_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/providers/aws.py") == ["safe"]


def test_transports_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/transports/stdio.py") == ["safe"]


def test_preprocessing_dir_safe() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/preprocessing/clean.py") == ["safe"]


def test_non_safe_dir_unknown() -> None:
    src = "def f(x): pass"
    assert _classify(src, file_path="app/server/handlers.py") == ["unknown"]


# ---------------------------------------------------------------------------
# Priority: decorator > file path > name
# ---------------------------------------------------------------------------

def test_tool_decorator_overrides_safe_dir() -> None:
    """@mcp.tool in a utils/ directory is still classified as 'tool'."""
    src = "@mcp.tool()\ndef f(x): pass"
    assert _classify(src, file_path="app/utils/tool.py") == ["tool"]


def test_cli_decorator_overrides_tool_name() -> None:
    """@click.command on a function named handle_tool is still 'safe'."""
    src = "@click.command()\ndef handle_tool(x): pass"
    assert _classify(src) == ["safe"]


def test_safe_dir_overrides_tool_name() -> None:
    """A function named handler in cli/ is 'safe' (dir beats name)."""
    src = "def handler(x): pass"
    assert _classify(src, file_path="app/cli/handler.py") == ["safe"]


# ---------------------------------------------------------------------------
# Nested functions
# ---------------------------------------------------------------------------

def test_nested_functions_each_classified() -> None:
    src = """
@mcp.tool()
def outer(x):
    def inner(y):
        pass
"""
    contexts = _classify(src)
    assert contexts == ["tool", "unknown"]


# ---------------------------------------------------------------------------
# Async functions
# ---------------------------------------------------------------------------

def test_async_function_classified() -> None:
    src = "@mcp.tool()\nasync def f(x): pass"
    assert _classify(src) == ["tool"]


def test_async_test_safe() -> None:
    src = "async def test_something(): pass"
    assert _classify(src) == ["safe"]
