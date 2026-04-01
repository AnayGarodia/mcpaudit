"""
Safe MCP tool handler: validates input and avoids shell=True.
This file is intentionally secure — used as a negative fixture for mcpaudit.
"""
import shlex
import subprocess

ALLOWED_COMMANDS = {"ls", "pwd", "echo", "date"}


def run_command(command: str) -> str:
    """Execute an allowlisted shell command with no shell interpolation."""
    parts = shlex.split(command)
    if not parts:
        raise ValueError("Empty command")
    if parts[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not permitted: {parts[0]!r}")
    result = subprocess.run(parts, shell=False, capture_output=True, text=True)
    return result.stdout


def list_file(filename: str) -> str:
    """List a file using a fixed argument list — no string interpolation."""
    # filename is passed as a literal argument, not shell-expanded
    result = subprocess.run(["ls", "-la", filename], capture_output=True, text=True)
    return result.stdout
