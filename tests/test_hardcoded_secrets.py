"""Tests for the hardcoded secrets detection rule."""
import ast
from pathlib import Path

from mcpaudit.rules.hardcoded_secrets import check_hardcoded_secrets

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


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


def test_password_name_detected() -> None:
    src = 'password = "hunter2supersecret"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1
    assert "password" in findings[0].description


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


def test_annotated_assignment_detected() -> None:
    src = 'client_secret: str = "realsecretvalue"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert len(findings) == 1


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


def test_env_var_not_flagged() -> None:
    src = 'import os\npassword = os.environ["PASSWORD"]'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_unrelated_variable_not_flagged() -> None:
    src = 'greeting = "hello world"'
    findings = check_hardcoded_secrets(ast.parse(src))
    assert findings == []


def test_multi_target_assign_deduplicated() -> None:
    src = 'a = api_key = "AKIAIOSFODNN7EXAMPLE1234"'
    findings = check_hardcoded_secrets(ast.parse(src))
    # Both targets match but the value is the same on the same line — one finding.
    assert len(findings) == 1, f"Expected 1 (deduplicated) finding, got {len(findings)}"


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("hardcoded_secrets_safe.py")
    findings = check_hardcoded_secrets(tree, file_path="hardcoded_secrets_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"
