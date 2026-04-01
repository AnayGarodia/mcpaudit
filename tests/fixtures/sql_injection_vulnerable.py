"""Fixture: SQL injection patterns that should be flagged."""
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def search_users(query: str) -> list:
    cursor = MagicMock()
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")  # CWE-89
    return cursor.fetchall()


@mcp.tool()
def get_record(table: str, record_id: str) -> dict:
    db = MagicMock()
    sql = "SELECT * FROM " + table + " WHERE id = " + record_id
    db.execute(sql)  # CWE-89: tainted via concatenation
    return {}


@mcp.tool()
def delete_rows(condition: str) -> None:
    conn = MagicMock()
    conn.execute("DELETE FROM logs WHERE " + condition)  # CWE-89
