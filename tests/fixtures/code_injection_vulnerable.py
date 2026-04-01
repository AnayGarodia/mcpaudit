"""Fixture: code injection patterns that should be flagged."""
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def run_expression(expression: str) -> str:
    result = eval(expression)  # CWE-95: tainted eval
    return str(result)


@mcp.tool()
def execute_code(code: str) -> str:
    exec(code)  # CWE-95: tainted exec
    return "done"


@mcp.tool()
def eval_with_intermediate(user_input: str) -> str:
    expr = f"({user_input})"
    result = eval(expr)  # CWE-95: tainted through f-string assignment
    return str(result)
