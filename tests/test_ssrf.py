"""Tests for the SSRF detection rule."""
import ast
from pathlib import Path

from mcpaudit.rules.ssrf import check_ssrf

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


def test_vulnerable_fixture_has_findings() -> None:
    tree = _parse("ssrf_vulnerable.py")
    findings = check_ssrf(tree, file_path="ssrf_vulnerable.py")

    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}: {findings}"
    for f in findings:
        assert f.cwe_id == "CWE-918"
        assert f.severity == "high"
        assert f.line > 0
        assert f.file_path == "ssrf_vulnerable.py"


def test_vulnerable_fixture_line_numbers() -> None:
    tree = _parse("ssrf_vulnerable.py")
    findings = check_ssrf(tree)
    lines = {f.line for f in findings}
    assert len(lines) == 4


def test_requests_get_detected() -> None:
    src = """
import requests

def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert "requests.get()" in findings[0].description


def test_httpx_get_detected() -> None:
    src = """
import httpx

def fetch(url: str) -> str:
    return httpx.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert "httpx.get()" in findings[0].description


def test_urllib_urlopen_detected() -> None:
    src = """
import urllib.request

def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url) as r:
        return r.read()
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert "urllib.request.urlopen()" in findings[0].description


def test_keyword_url_arg_detected() -> None:
    src = """
import requests

def fetch(endpoint: str) -> str:
    return requests.get(url=endpoint).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_assignment_detected() -> None:
    src = """
import requests

def fetch(base: str) -> str:
    full_url = f"https://{base}/api"
    return requests.get(full_url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_literal_url_not_flagged() -> None:
    src = """
import requests

def fetch(query: str) -> str:
    return requests.get("https://api.trusted.com/data").text
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("ssrf_safe.py")
    findings = check_ssrf(tree, file_path="ssrf_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"
