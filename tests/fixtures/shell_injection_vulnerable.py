"""
Vulnerable MCP tool handler: passes raw user input to subprocess with shell=True.
This file is intentionally insecure — used as a detection fixture for mcpaudit.
"""
import os
import subprocess
from unittest.mock import MagicMock

# Simulate an MCP server object with a @mcp.tool decorator.
mcp = MagicMock()


@mcp.tool()
def run_command(command: str) -> str:
    """Execute a shell command requested by the user."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_with_prefix(filename: str) -> str:
    """List a user-specified file."""
    result = subprocess.run(f"ls -la {filename}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_popen(cmd: str) -> str:
    """Open a subprocess with user-controlled command."""
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, _ = proc.communicate()
    return stdout.decode()


@mcp.tool()
def run_os_system(user_input: str) -> int:
    """Run a command via os.system — always shell-expanded."""
    return os.system(user_input)


@mcp.tool()
def run_os_popen(user_input: str) -> str:
    """Run a command via os.popen — always shell-expanded."""
    return os.popen(user_input).read()


@mcp.tool()
def run_via_variable(filename: str) -> str:
    """Taint flows through a local variable before reaching the sink."""
    command = f"cat {filename}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
