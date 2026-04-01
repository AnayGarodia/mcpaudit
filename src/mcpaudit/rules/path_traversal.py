"""
Rule: Path Traversal (CWE-22)

Detects user-controlled input flowing into file-open or path-construction
calls. Severity depends on the function's context:

  HIGH   — function is a confirmed MCP tool handler (decorator: @*.tool,
            @*.call_tool) or whose name suggests it's a tool handler
            (contains "tool", "handle", "execute", "handler").
            os.path.join with a tainted non-base argument is always HIGH.

  MEDIUM — function contains a path operation with user input but gives no
            clear signal that it is an MCP tool handler (unknown context).

  NOT FLAGGED — function is safe to ignore:
    • __init__ / __new__ (just store paths in attributes)
    • Decorated with a CLI framework decorator (@click.command, @typer.command,
      @*.command, @*.group)
    • Name starts with "test_"
    • Resides in a directory component named cli, commands, or config

Dangerous sinks:
  - open(tainted) / io.open(tainted)       — direct file open
  - os.open(tainted, ...)                  — low-level file open
  - Path(tainted) / pathlib.Path(tainted)  — path construction
  - os.path.join(base, tainted, ...)       — any non-first arg tainted

Limitations: alias imports (e.g. `from pathlib import Path as P`) and chained
calls (e.g. `Path(x).open()`) beyond the immediate builtin-sink check are not
tracked.
"""
import ast
from pathlib import Path as StdPath

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

_BUILTIN_SINKS: frozenset[str] = frozenset({"open", "Path"})

_ATTR_SINKS: frozenset[tuple[str, str]] = frozenset({
    ("io", "open"),
    ("os", "open"),
    ("pathlib", "Path"),
})

_TRIPLE_SINKS: frozenset[tuple[str, str, str]] = frozenset({
    ("os", "path", "join"),
})

# Decorator last-segment names that confirm an MCP tool handler.
_MCP_TOOL_DEC_ENDS: frozenset[str] = frozenset({"tool", "call_tool"})

# Decorator first-segment names for CLI frameworks — always safe.
_CLI_DEC_PREFIXES: frozenset[str] = frozenset({"click", "typer"})

# Decorator last-segment names that indicate CLI commands — always safe.
_CLI_DEC_NAME_ENDS: frozenset[str] = frozenset({"command", "group"})

# Function names whose invocation is safe to skip entirely.
_SAFE_FUNC_NAMES: frozenset[str] = frozenset({"__init__", "__new__", "__post_init__"})

# Directory path components that indicate developer-facing (non-tool) code.
_SAFE_PATH_DIRS: frozenset[str] = frozenset({"cli", "commands", "config"})

# Substrings in function names that suggest an MCP tool handler.
_TOOL_NAME_KEYWORDS: frozenset[str] = frozenset({"tool", "handle", "execute", "handler"})


def check_path_traversal(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user-controlled input reaches a file-path sink."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        # Stack of context strings: "tool", "safe", or "unknown"
        self._context_stack: list[str] = []

    # ------------------------------------------------------------------
    # Scope management — classify each function before visiting its body
    # ------------------------------------------------------------------

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        ctx = self._classify_function(node)
        self._context_stack.append(ctx)
        super()._visit_function(node)
        self._context_stack.pop()

    def _current_context(self) -> str:
        return self._context_stack[-1] if self._context_stack else "unknown"

    def _classify_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        """Return 'tool', 'safe', or 'unknown' for this function definition."""
        # Dunder methods just store/delegate — never a tool entry-point.
        if node.name in _SAFE_FUNC_NAMES:
            return "safe"

        # Check decorators (highest-signal indicator).
        for dec in node.decorator_list:
            name = self._decorator_name(dec)
            if name:
                parts = name.lower().split(".")
                last = parts[-1]
                first = parts[0]
                if last in _MCP_TOOL_DEC_ENDS:
                    return "tool"
                if first in _CLI_DEC_PREFIXES or last in _CLI_DEC_NAME_ENDS:
                    return "safe"

        # File path heuristics: developer-facing directories.
        if self._file_in_safe_dir():
            return "safe"

        # Test function names.
        if node.name.startswith("test_"):
            return "safe"

        # Function name suggests a tool/handler entry-point.
        name_lower = node.name.lower()
        if any(kw in name_lower for kw in _TOOL_NAME_KEYWORDS):
            return "tool"

        return "unknown"

    def _file_in_safe_dir(self) -> bool:
        """True if any *directory* component of the current file path is a safe dir."""
        # Exclude the filename itself (last part) — only check parent directories.
        parent_parts = StdPath(self.file_path).parts[:-1]
        return any(p in _SAFE_PATH_DIRS for p in parent_parts)

    @staticmethod
    def _decorator_name(dec: ast.expr) -> str | None:
        """Extract 'a.b.c' from a decorator node (Name, Attribute, or Call)."""
        if isinstance(dec, ast.Call):
            return _Visitor._decorator_name(dec.func)
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Attribute):
            parts: list[str] = []
            node: ast.expr = dec
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
                return ".".join(reversed(parts))
        return None

    # ------------------------------------------------------------------
    # Sink detection
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        # Builtin-name sinks: open(x), Path(x)
        if isinstance(node.func, ast.Name) and node.func.id in _BUILTIN_SINKS:
            self._check_first_arg(node, f"{node.func.id}()")

        pair = self._attr_pair(node)
        if pair is not None and pair in _ATTR_SINKS:
            self._check_first_arg(node, f"{pair[0]}.{pair[1]}()")

        triple = self._attr_triple(node)
        if triple is not None and triple in _TRIPLE_SINKS:
            self._check_join_args(node)

        self.generic_visit(node)

    def _check_first_arg(self, node: ast.Call, label: str) -> None:
        if not (node.args and self._is_tainted(node.args[0])):
            return
        ctx = self._current_context()
        if ctx == "safe":
            return
        severity = "high" if ctx == "tool" else "medium"
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity=severity,
            cwe_id="CWE-22",
            description=(
                f"User-controlled input passed to {label}; "
                "an attacker may read or write arbitrary files via path traversal."
            ),
            remediation=(
                "Resolve the path with Path(user_input).resolve() and verify it "
                "starts with the intended base directory before opening."
            ),
        ))

    def _check_join_args(self, node: ast.Call) -> None:
        """Flag os.path.join when any non-first argument is tainted (always HIGH)."""
        if self._current_context() == "safe":
            return
        for arg in node.args[1:]:
            if self._is_tainted(arg):
                self.findings.append(Finding(
                    file_path=self.file_path,
                    line=node.lineno,
                    severity="high",
                    cwe_id="CWE-22",
                    description=(
                        "User-controlled input in a non-base argument to os.path.join(); "
                        "an attacker can inject '../' sequences to escape the base directory."
                    ),
                    remediation=(
                        "After joining, call Path(result).resolve() and assert the result "
                        "starts with the expected base directory."
                    ),
                ))
                return  # one finding per call site is enough
