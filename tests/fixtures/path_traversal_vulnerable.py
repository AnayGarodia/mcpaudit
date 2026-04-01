"""
Vulnerable MCP tool handler: passes raw user input to file-path sinks.
This file is intentionally insecure — used as a detection fixture for mcpaudit.
"""
import io
import os
import pathlib
from unittest.mock import MagicMock

# Simulate an MCP server object with a @mcp.tool decorator.
mcp = MagicMock()


@mcp.tool()
def read_file(filename: str) -> str:
    """Open a user-specified file directly."""
    with open(filename) as f:
        return f.read()


@mcp.tool()
def read_file_io(filename: str) -> str:
    """Open via io.open with user-supplied path."""
    with io.open(filename) as f:
        return f.read()


@mcp.tool()
def read_file_os(filename: str) -> int:
    """Low-level open via os.open."""
    return os.open(filename, os.O_RDONLY)


@mcp.tool()
def make_path(user_dir: str) -> pathlib.Path:
    """Construct a Path from user input."""
    return pathlib.Path(user_dir)


@mcp.tool()
def list_subdir(subdir: str) -> str:
    """List files in a user-specified subdirectory under /data."""
    full_path = os.path.join("/data", subdir)
    return full_path
