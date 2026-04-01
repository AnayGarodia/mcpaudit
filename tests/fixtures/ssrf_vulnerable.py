"""
Vulnerable MCP tool handler: passes raw user input as a URL to HTTP clients.
This file is intentionally insecure — used as a detection fixture for mcpaudit.
"""
import urllib.request
from unittest.mock import MagicMock

import httpx
import requests

# Simulate an MCP server object with a @mcp.tool decorator.
mcp = MagicMock()


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL supplied directly by the user."""
    return requests.get(url).text


@mcp.tool()
def post_data(endpoint: str, data: dict) -> str:
    """POST to a user-controlled endpoint."""
    return requests.post(endpoint, json=data).text


@mcp.tool()
def fetch_httpx(url: str) -> str:
    """Fetch via httpx with user-controlled URL."""
    return httpx.get(url).text


@mcp.tool()
def fetch_urllib(url: str) -> bytes:
    """Fetch via urllib with user-controlled URL."""
    with urllib.request.urlopen(url) as resp:
        return resp.read()
