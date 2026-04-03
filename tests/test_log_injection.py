"""Comprehensive tests for the log injection detection rule (CWE-117)."""
import ast
from pathlib import Path

from mcpaudit.rules.log_injection import check_log_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("log_injection_vulnerable.py")
    findings = check_log_injection(tree, file_path="log_injection_vulnerable.py")

    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-117"
        assert f.severity == "high"
        assert f.line > 0


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("log_injection_safe.py")
    findings = check_log_injection(tree, file_path="log_injection_safe.py")
    assert findings == [], f"Unexpected findings: {findings}"


# ---------------------------------------------------------------------------
# Sink detection — module-level logging.*
# ---------------------------------------------------------------------------

def test_logging_info_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1
    assert "logging.info()" in findings[0].description


def test_logging_warning_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.warning(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


def test_logging_error_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.error(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


def test_logging_debug_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.debug(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


def test_logging_critical_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.critical(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Sink detection — logger instance
# ---------------------------------------------------------------------------

def test_logger_instance_info_detected() -> None:
    src = """
import logging

logger = logging.getLogger(__name__)

@mcp.tool()
def process(msg: str):
    logger.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1
    assert "<logger>.info()" in findings[0].description


def test_logger_instance_error_detected() -> None:
    src = """
import logging

logger = logging.getLogger("app")

@mcp.tool()
def process(msg: str):
    logger.error(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def test_taint_through_fstring_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(user_input: str):
    logging.info(f"Received: {user_input}")
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_assignment_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(user_input: str):
    msg = user_input
    logging.warning(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_concatenation_detected() -> None:
    src = """
import logging

@mcp.tool()
def process(user_input: str):
    logging.info("User said: " + user_input)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Safe patterns — not flagged
# ---------------------------------------------------------------------------

def test_parameterized_logging_not_flagged() -> None:
    """logging.info("fmt: %s", user_input) — first arg is static, NOT flagged."""
    src = """
import logging

@mcp.tool()
def process(user_input: str):
    logging.info("User input: %s", user_input)
"""
    findings = check_log_injection(ast.parse(src))
    assert findings == []


def test_static_message_not_flagged() -> None:
    src = """
import logging

@mcp.tool()
def process(event_type: str):
    logging.info("Event received")
"""
    findings = check_log_injection(ast.parse(src))
    assert findings == []


def test_logger_parameterized_not_flagged() -> None:
    src = """
import logging

logger = logging.getLogger(__name__)

@mcp.tool()
def process(username: str):
    logger.warning("Login attempt for: %s", username)
"""
    findings = check_log_injection(ast.parse(src))
    assert findings == []


def test_untracked_logger_not_flagged() -> None:
    """logger not from getLogger() — not tracked, no false positives."""
    src = """
from mylib import get_logger

logger = get_logger(__name__)

@mcp.tool()
def process(msg: str):
    logger.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Context classification
# ---------------------------------------------------------------------------

def test_tool_decorator_severity_high() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unknown_context_severity_medium() -> None:
    src = """
import logging

def process_something(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_safe_context_not_flagged() -> None:
    src = """
import logging

@classmethod
def process(cls, msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert findings == []


def test_test_function_not_flagged() -> None:
    src = """
import logging

def test_logging(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert findings == []


def test_cli_dir_not_flagged() -> None:
    src = """
import logging

def process(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src), file_path="app/cli/handler.py")
    assert findings == []


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------

def test_rule_id_and_cwe() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert findings[0].rule_id == "log_injection"
    assert findings[0].cwe_id == "CWE-117"


def test_remediation_mentions_parameterized() -> None:
    src = """
import logging

@mcp.tool()
def process(msg: str):
    logging.info(msg)
"""
    findings = check_log_injection(ast.parse(src))
    assert "parameterized" in findings[0].remediation.lower() or "%" in findings[0].remediation
