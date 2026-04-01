"""Shared data types for mcpaudit findings."""
from dataclasses import dataclass


@dataclass
class Finding:
    """A single security finding produced by a rule."""

    file_path: str
    line: int
    severity: str  # low | medium | high | critical
    cwe_id: str
    description: str
    remediation: str
