"""
Safe MCP tool handlers: use parameterized logging or static messages.
This file should produce zero log injection findings.
"""
import logging
from unittest.mock import MagicMock

mcp = MagicMock()
logger = logging.getLogger(__name__)


@mcp.tool()
def log_parameterized(user_input: str) -> str:
    """Use parameterized logging — SAFE (static format string as first arg)."""
    logging.info("User input received: %s", user_input)
    return "ok"


@mcp.tool()
def log_static_message(event_type: str) -> str:
    """Log a static message — SAFE (no user input in message)."""
    logging.info("Event received")
    return event_type


@mcp.tool()
def log_via_logger_parameterized(username: str) -> str:
    """Logger with parameterized call — SAFE."""
    logger.warning("Login attempt for user: %s", username)
    return "logged"


@mcp.tool()
def log_event_count(count: int) -> str:
    """Log a static format string — SAFE."""
    logging.debug("Processed events successfully")
    return str(count)
