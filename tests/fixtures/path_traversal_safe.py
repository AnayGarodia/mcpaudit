"""
Safe file access: validates and resolves paths before opening.
This file is intentionally secure — used as a negative fixture for mcpaudit.
"""
import os
from pathlib import Path

BASE_DIR = Path("/var/data")
ALLOWED_FILES = {"report.txt", "summary.csv"}


def read_file(filename: str) -> str:
    """Only open files from an explicit allowlist."""
    if filename not in ALLOWED_FILES:
        raise ValueError(f"File not permitted: {filename!r}")
    with open(BASE_DIR / filename) as f:
        return f.read()


def read_resolved(user_path: str) -> str:
    """Resolve and verify the path stays within the base directory."""
    resolved = (BASE_DIR / user_path).resolve()
    if not str(resolved).startswith(str(BASE_DIR)):
        raise ValueError("Path traversal detected")
    with open(resolved) as f:
        return f.read()


def join_safe() -> str:
    """os.path.join with only literal arguments — no taint."""
    return os.path.join("/static", "assets", "logo.png")
