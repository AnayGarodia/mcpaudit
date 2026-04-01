"""Fixture: code patterns that should NOT be flagged for code injection."""
import ast as _ast


def parse_literal(value: str) -> object:
    # ast.literal_eval is safe — only parses Python literals, not arbitrary code.
    return _ast.literal_eval(value)


def eval_hardcoded() -> int:
    # Hardcoded expression — not user-controlled.
    return eval("1 + 2")  # noqa


def exec_hardcoded() -> None:
    # Hardcoded code — not user-controlled.
    exec("x = 1")  # noqa
