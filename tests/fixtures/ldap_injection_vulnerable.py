"""
Vulnerable MCP tool handlers: pass raw user input into LDAP search filters.
This file is intentionally insecure — used as a detection fixture for mcpaudit.

Expected findings: 3
"""
import ldap
import ldap3
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def search_user(username: str) -> list:
    """Search LDAP for a user — filter injection risk (positional arg)."""
    conn = ldap.initialize("ldap://localhost")
    results = conn.search_s(
        "dc=example,dc=com",
        ldap.SCOPE_SUBTREE,
        f"(uid={username})",
    )
    return results


@mcp.tool()
def search_ldap3_positional(username: str) -> list:
    """Search via ldap3 with tainted filter in positional arg — injection risk."""
    server = ldap3.Server("localhost")
    conn = ldap3.Connection(server, auto_bind=True)
    conn.search(
        "dc=example,dc=com",
        f"(uid={username})",
    )
    return conn.entries


@mcp.tool()
def search_ldap3_keyword(group_name: str) -> list:
    """Search via ldap3 with tainted filter as keyword arg — injection risk."""
    server = ldap3.Server("localhost")
    conn = ldap3.Connection(server, auto_bind=True)
    conn.search(
        "dc=example,dc=com",
        search_filter=f"(cn={group_name})",
    )
    return conn.entries
