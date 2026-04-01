"""Fixture: SQL patterns that should NOT be flagged."""


def search_users_safe(query: str) -> list:
    cursor = None  # type: ignore[assignment]
    # Parameterized query — safe
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{query}%",))
    return cursor.fetchall()


def static_query() -> list:
    cursor = None  # type: ignore[assignment]
    # Hardcoded query — not user-controlled
    cursor.execute("SELECT * FROM users WHERE active = 1")
    return cursor.fetchall()
