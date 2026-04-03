"""
Safe MCP tool handlers: use static LDAP filters or escaped input.
This file should produce zero LDAP injection findings.
"""
import ldap3
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def search_all_users(department: str) -> list:
    """Search with a static filter — SAFE (no user input in filter)."""
    server = ldap3.Server("localhost")
    conn = ldap3.Connection(server, auto_bind=True)
    conn.search("dc=example,dc=com", "(objectClass=person)")
    return conn.entries


@mcp.tool()
def search_by_role(role: str) -> list:
    """Lookup from an allowlist via subscript — SAFE (container is not tainted)."""
    allowed = {"admin": "(cn=Admins)", "user": "(cn=Users)"}
    if role not in allowed:
        return []
    ldap_filter = allowed[role]
    server = ldap3.Server("localhost")
    conn = ldap3.Connection(server, auto_bind=True)
    conn.search("dc=example,dc=com", ldap_filter)
    return conn.entries
