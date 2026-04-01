"""Comprehensive tests for the hardcoded secrets detection rule (CWE-798)."""
import ast
from pathlib import Path

from mcpaudit.rules.hardcoded_secrets import check_hardcoded_secrets

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("hardcoded_secrets_vulnerable.py")
    findings = check_hardcoded_secrets(tree, file_path="hardcoded_secrets_vulnerable.py")

    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-798"
        assert f.severity == "high"
        assert f.line > 0
        assert f.file_path == "hardcoded_secrets_vulnerable.py"


def test_vulnerable_fixture_line_numbers() -> None:
    tree = _parse("hardcoded_secrets_vulnerable.py")
    findings = check_hardcoded_secrets(tree)
    lines = {f.line for f in findings}
    assert len(lines) == 4


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("hardcoded_secrets_safe.py")
    findings = check_hardcoded_secrets(tree, file_path="hardcoded_secrets_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


# ---------------------------------------------------------------------------
# Mode 1: Variable name matching
# ---------------------------------------------------------------------------

def test_password_name_detected() -> None:
    src = 'password = "hunter2supersecret"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1
    assert "password" in findings[0].description


def test_api_key_detected() -> None:
    src = 'api_key = "sk_live_realkey1234567890"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_token_detected() -> None:
    src = 'token = "realtoken1234567890"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_secret_name_detected() -> None:
    src = 'secret = "supersecretvalue123"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_auth_token_detected() -> None:
    src = 'auth_token = "Bearer realtoken123456"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_private_key_detected() -> None:
    src = 'private_key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_client_secret_detected() -> None:
    src = 'client_secret = "realsecretvalue"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_access_key_detected() -> None:
    src = 'access_key = "realAccessKey123456"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_passwd_detected() -> None:
    src = 'passwd = "database_password_real"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_secret_key_detected() -> None:
    src = 'secret_key = "django-insecure-realsecret"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_annotated_assignment_detected() -> None:
    src = 'client_secret: str = "realsecretvalue"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Mode 2: Known key format regexes
# ---------------------------------------------------------------------------

def test_aws_key_pattern_detected() -> None:
    src = 'key = "AKIAIOSFODNN7EXAMPLE1234"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-798"


def test_openai_key_pattern_detected() -> None:
    src = f'key = "sk-{"A" * 48}"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_github_token_pattern_detected() -> None:
    src = 'token = "ghs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_github_pat_pattern_detected() -> None:
    src = 'token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


def test_regex_matches_regardless_of_name() -> None:
    """AWS key format should be detected even if variable name is innocent."""
    src = 'config_value = "AKIAIOSFODNN7EXAMPLE1234"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Placeholder values — NOT flagged
# ---------------------------------------------------------------------------

def test_placeholder_not_flagged() -> None:
    src = 'password = "changeme"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_empty_string_not_flagged() -> None:
    src = 'api_key = ""'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_your_prefix_not_flagged() -> None:
    src = 'api_key = "your_api_key_here"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_angle_bracket_placeholder_not_flagged() -> None:
    src = 'api_key = "<your-api-key>"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_xxx_placeholder_not_flagged() -> None:
    src = 'password = "xxx"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_dummy_value_not_flagged() -> None:
    src = 'api_key = "dummy-key-for-unauthenticated-endpoint"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_fake_value_not_flagged() -> None:
    src = 'token = "fake-token-for-testing"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_example_value_not_flagged() -> None:
    src = 'secret = "example-secret-not-real"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_test_value_not_flagged() -> None:
    src = 'password = "test"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_password_literal_not_flagged() -> None:
    """The word 'password' as a value is a placeholder, not a real password."""
    src = 'password = "password"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Non-secret variables — NOT flagged
# ---------------------------------------------------------------------------

def test_env_var_not_flagged() -> None:
    src = 'import os\npassword = os.environ["PASSWORD"]'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_unrelated_variable_not_flagged() -> None:
    src = 'greeting = "hello world"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_integer_value_not_flagged() -> None:
    src = 'password = 12345'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_function_call_value_not_flagged() -> None:
    src = 'password = get_password()'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_fstring_value_not_flagged() -> None:
    src = 'api_key = f"prefix-{os.getenv(\'KEY\')}"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_multi_target_assign_deduplicated() -> None:
    src = 'a = api_key = "AKIAIOSFODNN7EXAMPLE1234"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Description and remediation
# ---------------------------------------------------------------------------

def test_description_includes_variable_name() -> None:
    src = 'password = "realsecret123"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert "password" in findings[0].description


def test_description_includes_value_preview() -> None:
    src = 'password = "verylongsecretvalue123456"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert "verylo..." in findings[0].description


def test_remediation_mentions_env_vars() -> None:
    src = 'password = "realsecret123"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert "environment" in findings[0].remediation
