"""
Rule: SQL Injection (CWE-89)

Detects user-controlled input flowing into database execute() calls as a
non-parameterized query string. Parameterized queries (cursor.execute(sql, params))
are NOT flagged as they use safe binding.

Severity depends on the function's context (inherited from TaintVisitor):

  HIGH   — function is a confirmed MCP tool handler or name suggests a handler.
  MEDIUM — unknown context.
  NOT FLAGGED — function is classified as "safe" (CLI, classmethod, utils, etc.).

Dangerous sinks:
  - cursor.execute(tainted_query)          — raw string, no params
  - connection.execute(tainted_query)      — SQLAlchemy / sqlite3
  - session.execute(tainted_query)         — SQLAlchemy ORM
  - db.execute(tainted_query)              — common pattern

Detection: `.execute(first_arg)` call where ALL of:
  1. The calling object's name contains a database-related keyword
     (cursor, conn, connection, db, session, engine, database, sqlite, pg, psycopg)
  2. The first argument is a tainted string (f-string, concatenation, variable)
  3. No second positional argument is present (which would indicate parameterization)

The object-name check prevents false positives from `.execute()` calls on
non-SQL objects (e.g., tool runners, subprocess managers, async executors).

Limitations: alias imports and chained ORM calls are not tracked.
"""
import ast

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# Substrings in a variable/attribute name that suggest it holds a DB connection/cursor.
_DB_NAME_KEYWORDS: frozenset[str] = frozenset({
    "cursor", "conn", "connection", "db", "database", "session",
    "engine", "sqlite", "pg", "psycopg", "mysql", "query",
})


def _is_db_object(node: ast.expr) -> bool:
    """Return True if the node looks like a database connection/cursor object."""
    if isinstance(node, ast.Name):
        lower = node.id.lower()
        return any(kw in lower for kw in _DB_NAME_KEYWORDS)
    if isinstance(node, ast.Attribute):
        lower = node.attr.lower()
        return any(kw in lower for kw in _DB_NAME_KEYWORDS)
    return False


def check_sql_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches a SQL execute() sink."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            # Object name must suggest a database connection
            and _is_db_object(node.func.value)
            # Must have at least one arg (the query)
            and node.args
            # First arg must be tainted
            and self._is_tainted(node.args[0])
            # If a second positional arg exists it's parameterized — skip
            and len(node.args) < 2
        ):
            ctx = self._current_context()
            if ctx != "safe":
                severity = "high" if ctx == "tool" else "medium"
                # Derive a human-readable object name from the call
                func_obj = node.func.value
                if isinstance(func_obj, ast.Name):
                    obj_label = func_obj.id
                elif isinstance(func_obj, ast.Attribute):
                    obj_label = func_obj.attr
                else:
                    obj_label = "db"
                self.findings.append(Finding(
                    file_path=self.file_path,
                    line=node.lineno,
                    severity=severity,
                    cwe_id="CWE-89",
                    rule_id="sql_injection",
                    description=(
                        f"User-controlled input passed as a raw SQL query to "
                        f"{obj_label}.execute(); an attacker can manipulate the query "
                        "to read, modify, or delete arbitrary data."
                    ),
                    remediation=(
                        "Use parameterized queries: cursor.execute(sql, (param,)) or "
                        "an ORM with bound parameters. Never interpolate user input "
                        "directly into SQL strings."
                    ),
                ))
        self.generic_visit(node)
