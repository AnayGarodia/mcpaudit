"""
Safe MCP tool handlers — demonstrate patterns that should NOT trigger the
prompt injection rule.
This file is intentionally secure — used as a negative fixture for mcpaudit.
"""
import requests


def greet(name: str) -> str:
    """Simple echo — no instruction keywords in the static f-string parts."""
    return f"Hello, {name}! How can I help?"


def count_words(text: str) -> str:
    """Returns a computed result, not raw user input or external content."""
    count = len(text.split())
    return f"Word count: {count}"


def error_response(user_input: str) -> str:
    """Error message that includes the input — no instruction keywords."""
    return f"Error: '{user_input}' is not a valid value."


def fetch_fixed_url() -> str:
    """Fetches from a hardcoded URL — no user-controlled fetch target."""
    return requests.get("https://api.trusted.com/status").text


def summarize_request(query: str) -> str:
    """Transforms parameter into a label — no instruction-keyword context."""
    return f"Received query: {query}"


def echo_tool() -> str:
    """No user input at all."""
    return "Tool executed successfully."
