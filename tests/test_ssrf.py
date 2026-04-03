"""Comprehensive tests for the SSRF detection rule (CWE-918)."""
import ast
from pathlib import Path

from mcpaudit.rules.ssrf import check_ssrf

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ast.Module:
    src = (FIXTURES / name).read_text()
    return ast.parse(src)


# ---------------------------------------------------------------------------
# Fixture-level tests
# ---------------------------------------------------------------------------

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


def test_safe_fixture_has_no_findings() -> None:
    tree = _parse("ssrf_safe.py")
    findings = check_ssrf(tree, file_path="ssrf_safe.py")
    assert findings == [], f"Unexpected findings in safe fixture: {findings}"


# ---------------------------------------------------------------------------
# Sink detection — each HTTP library
# ---------------------------------------------------------------------------

def test_requests_get_detected() -> None:
    src = """
import requests

def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert "requests.get()" in findings[0].description


def test_requests_post_detected() -> None:
    src = """
import requests

def send(endpoint: str) -> str:
    return requests.post(endpoint, json={}).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_requests_put_detected() -> None:
    src = """
import requests

def update(url: str) -> str:
    return requests.put(url, json={}).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_requests_delete_detected() -> None:
    src = """
import requests

def remove(url: str) -> str:
    return requests.delete(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_requests_request_detected() -> None:
    src = """
import requests

def generic(method: str, url: str) -> str:
    return requests.request(method, url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_httpx_get_detected() -> None:
    src = """
import httpx

def fetch(url: str) -> str:
    return httpx.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert "httpx.get()" in findings[0].description


def test_httpx_post_detected() -> None:
    src = """
import httpx

def send(url: str) -> str:
    return httpx.post(url, json={}).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


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


# ---------------------------------------------------------------------------
# URL argument detection
# ---------------------------------------------------------------------------

def test_keyword_url_arg_detected() -> None:
    src = """
import requests

def fetch(endpoint: str) -> str:
    return requests.get(url=endpoint).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_positional_url_preferred_over_keyword() -> None:
    """When URL is positional, keyword url= should not also trigger."""
    src = """
import requests

def fetch(url: str) -> str:
    return requests.get(url, timeout=10).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Taint propagation
# ---------------------------------------------------------------------------

def test_taint_through_assignment_detected() -> None:
    src = """
import requests

def fetch(base: str) -> str:
    full_url = f"https://{base}/api"
    return requests.get(full_url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_concat_detected() -> None:
    src = """
import requests

def fetch(host: str) -> str:
    url = "https://" + host + "/api"
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_taint_through_call_return() -> None:
    src = """
import requests

def fetch(user_input: str) -> str:
    url = build_url(user_input)
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Context classification — tool decorator → HIGH
# ---------------------------------------------------------------------------

def test_mcp_tool_decorator_severity_high() -> None:
    src = """
import requests

@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_handler_name_severity_high() -> None:
    src = """
import requests

def handle_fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_unknown_context_severity_medium() -> None:
    src = """
import requests

def download(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# Context classification — safe contexts → NOT flagged
# ---------------------------------------------------------------------------

def test_click_command_not_flagged() -> None:
    src = """
import requests, click

@click.command()
def cli_fetch(url: str) -> None:
    print(requests.get(url).text)
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_init_method_not_flagged() -> None:
    src = """
import requests

class Client:
    def __init__(self, url: str) -> None:
        self.data = requests.get(url).json()
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_classmethod_not_flagged() -> None:
    src = """
import httpx

class OIDCConfig:
    @classmethod
    def from_url(cls, config_url: str):
        response = httpx.get(config_url)
        return cls(response.json())
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_staticmethod_not_flagged() -> None:
    src = """
import requests

class Fetcher:
    @staticmethod
    def fetch(url: str) -> str:
        return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_test_function_not_flagged() -> None:
    src = """
import requests

def test_fetch(url: str) -> None:
    resp = requests.get(url)
    assert resp.status_code == 200
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_safe_dir_cli_not_flagged() -> None:
    src = """
import requests

def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src), file_path="app/cli/download.py")
    assert findings == []


def test_safe_dir_auth_not_flagged() -> None:
    src = """
import httpx

def get_config(url: str) -> dict:
    return httpx.get(url).json()
"""
    findings = check_ssrf(ast.parse(src), file_path="server/auth/oidc.py")
    assert findings == []


def test_tool_decorator_overrides_safe_dir() -> None:
    src = """
import requests

@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src), file_path="app/auth/fetcher.py")
    assert len(findings) == 1
    assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# False-positive prevention
# ---------------------------------------------------------------------------

def test_literal_url_not_flagged() -> None:
    src = """
import requests

def fetch(query: str) -> str:
    return requests.get("https://api.trusted.com/data").text
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_no_args_not_flagged() -> None:
    src = """
import requests

def bad():
    return requests.get().text
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_async_function_detected() -> None:
    src = """
import httpx

@mcp.tool()
async def fetch(url: str) -> str:
    return httpx.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_remediation_present() -> None:
    src = """
import requests

def fetch(url: str) -> str:
    return requests.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert "allowlist" in findings[0].remediation


# ---------------------------------------------------------------------------
# Session-based SSRF
# ---------------------------------------------------------------------------

def test_requests_session_get_detected() -> None:
    src = """
import requests

@mcp.tool()
def fetch(url: str) -> str:
    session = requests.Session()
    return session.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-918"


def test_requests_session_post_detected() -> None:
    src = """
import requests

@mcp.tool()
def send(url: str, data: dict) -> str:
    session = requests.Session()
    return session.post(url, json=data).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_httpx_client_get_detected() -> None:
    src = """
import httpx

@mcp.tool()
def fetch(url: str) -> str:
    client = httpx.Client()
    return client.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_httpx_async_client_detected() -> None:
    src = """
import httpx

@mcp.tool()
async def fetch(url: str) -> str:
    client = httpx.AsyncClient()
    return (await client.get(url)).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_aiohttp_client_session_detected() -> None:
    src = """
import aiohttp

@mcp.tool()
async def fetch(url: str) -> str:
    session = aiohttp.ClientSession()
    return await session.get(url)
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_session_static_url_not_flagged() -> None:
    src = """
import requests

@mcp.tool()
def fetch(query: str) -> str:
    session = requests.Session()
    return session.get("https://api.trusted.com/data").text
"""
    findings = check_ssrf(ast.parse(src))
    assert findings == []


def test_non_session_var_not_flagged() -> None:
    """A var named 'session' that wasn't assigned from a session constructor."""
    src = """
import requests

@mcp.tool()
def fetch(url: str) -> str:
    session = get_session_from_cache()
    return session.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    # session.get() is not a recognized HTTP sink unless session is from _SESSION_CONSTRUCTORS
    assert findings == []


# ---------------------------------------------------------------------------
# Import alias tracking
# ---------------------------------------------------------------------------

def test_import_alias_requests_detected() -> None:
    src = """
import requests as req

@mcp.tool()
def fetch(url: str) -> str:
    return req.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1


def test_import_alias_httpx_detected() -> None:
    src = """
import httpx as hx

@mcp.tool()
def fetch(url: str) -> str:
    return hx.get(url).text
"""
    findings = check_ssrf(ast.parse(src))
    assert len(findings) == 1
