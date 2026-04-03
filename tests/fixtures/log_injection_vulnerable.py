"""
Vulnerable MCP tool handlers: pass raw user input as the log message.
This file is intentionally insecure — used as a detection fixture for mcpaudit.

Expected findings: 4
"""
import logging
from unittest.mock import MagicMock

mcp = MagicMock()
logger = logging.getLogger(__name__)


@mcp.tool()
def process_request(user_message: str) -> str:
    """Log user message directly — log injection risk."""
    logging.info(user_message)
    return "ok"


@mcp.tool()
def log_user_action(action: str) -> str:
    """Log via module with f-string — injection risk."""
    logging.warning(f"User action: {action}")
    return "logged"


@mcp.tool()
def log_via_logger(user_input: str) -> str:
    """Log via logger instance — injection risk."""
    logger.error(user_input)
    return "error logged"


@mcp.tool()
def log_via_logger_fstring(username: str) -> str:
    """Log via logger instance with f-string — injection risk."""
    logger.debug(f"Login attempt: {username}")
    return "debug logged"
