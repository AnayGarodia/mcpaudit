"""Fixture: unsafe deserialization patterns that should be flagged."""
import pickle
import yaml
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def load_object(data: bytes) -> object:
    return pickle.loads(data)  # CWE-502


@mcp.tool()
def parse_config(config_str: str) -> dict:
    return yaml.load(config_str, Loader=yaml.FullLoader)  # CWE-502: FullLoader is unsafe


@mcp.tool()
def parse_config_no_loader(config_str: str) -> dict:
    return yaml.load(config_str)  # CWE-502: no Loader specified
