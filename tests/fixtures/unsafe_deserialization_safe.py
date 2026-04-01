"""Fixture: deserialization patterns that should NOT be flagged."""
import json
import pickle
import yaml


def load_from_trusted_file() -> object:
    # Hardcoded path — not user-controlled
    with open("/var/cache/app/state.pkl", "rb") as f:
        return pickle.load(f)


def parse_yaml_safe(config_str: str) -> dict:
    # yaml.safe_load uses SafeLoader — safe
    return yaml.safe_load(config_str)


def parse_yaml_explicit_safe(config_str: str) -> dict:
    # Explicit SafeLoader — safe
    return yaml.load(config_str, Loader=yaml.SafeLoader)


def parse_json(data: str) -> object:
    # JSON is safe to parse
    return json.loads(data)
