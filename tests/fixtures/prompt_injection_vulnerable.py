"""
Vulnerable MCP tool handlers for prompt injection detection.
Each function demonstrates a genuine prompt injection risk.
This file is intentionally insecure — used as a detection fixture for mcpaudit.
"""
import subprocess
import requests


def fetch_from_url(url: str) -> str:
    """Pattern 1: HTTP response content returned to LLM (fetch passthrough)."""
    response = requests.get(url)
    return response.text  # fetch-tainted via tainted response variable


def read_local_file(path: str) -> str:
    """Pattern 2: File content returned to LLM (fetch passthrough)."""
    return open(path).read()  # external fetch call chained into return


def run_command(cmd: str) -> str:
    """Pattern 3: Subprocess output returned to LLM (fetch passthrough)."""
    return subprocess.check_output(cmd, shell=True).decode("utf-8")


def set_persona(role: str) -> str:
    """Pattern 4: User input interpolated into LLM instruction string."""
    return f"You are {role}. Act as {role} from now on."


def build_system_prompt(instructions: str) -> str:
    """Pattern 5: Instruction injection through a local variable."""
    system_msg = f"System: {instructions}\nAssistant: understood."
    return system_msg  # instruction-tainted variable
