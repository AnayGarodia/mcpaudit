"""
Shared taint-tracking visitor base for mcpaudit rules.

TaintVisitor provides:
  1. Per-function-scope taint propagation (param → local-var → sink)
  2. Function context classification — determines whether a function is a
     confirmed MCP tool handler ("tool"), safe developer-facing code ("safe"),
     or of unknown purpose ("unknown").  Rules use this to adjust severity or
     skip entirely for low-signal contexts.
"""
import ast
from pathlib import Path as _StdPath

# ---------------------------------------------------------------------------
# Context classification constants
# ---------------------------------------------------------------------------

# Decorator last-segment names that confirm an MCP tool handler.
_MCP_TOOL_DEC_ENDS: frozenset[str] = frozenset({"tool", "call_tool"})

# Decorator first-segment names (library prefix) for CLI frameworks.
_CLI_DEC_PREFIXES: frozenset[str] = frozenset({"click", "typer"})

# Decorator last-segment names indicating CLI commands/groups.
_CLI_DEC_NAME_ENDS: frozenset[str] = frozenset({"command", "group"})

# Single-word decorators that indicate non-tool utility/class methods.
_SAFE_SINGLE_DECORATORS: frozenset[str] = frozenset({
    "classmethod", "staticmethod", "property",
})

# Function names that are never tool entry-points.
_SAFE_FUNC_NAMES: frozenset[str] = frozenset({
    "__init__", "__new__", "__post_init__",
})

# Directory path components that indicate developer-facing / framework-internal
# code.  Functions in these directories default to "safe" context when no
# explicit tool decorator is present.  The decorator check runs first so that
# a @mcp.tool in a utilities/ directory is still classified as "tool".
_SAFE_PATH_DIRS: frozenset[str] = frozenset({
    "cli",              # CLI entry-points (user's own machine, not LLM-facing)
    "commands",         # CLI command definitions
    "config",           # Configuration loaders
    "utilities",        # Internal helper/utility code
    "utils",            # Internal utility code (common alias)
    "transports",       # Framework transport layer
    "providers",        # Internal provider implementations
    "preprocessing",    # Data preprocessing / conversion code
    "models",           # Data models / schemas
    "middleware",       # Framework middleware
    "auth",             # Authentication / authorization implementations
})

# Substrings in a function name that suggest it is a tool/handler entry-point
# when no explicit decorator is present.
_TOOL_NAME_KEYWORDS: frozenset[str] = frozenset({
    "tool", "handle", "execute", "handler",
})


def _get_decorator_name(dec: ast.expr) -> str | None:
    """Recursively extract 'a.b.c' string from a decorator node.

    Handles plain names (@tool), attribute chains (@mcp.tool), and calls
    (@mcp.tool() or @click.command(help='...')).
    Returns None for decorator expressions that don't match these patterns.
    """
    if isinstance(dec, ast.Call):
        return _get_decorator_name(dec.func)
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


# ---------------------------------------------------------------------------
# TaintVisitor
# ---------------------------------------------------------------------------

class TaintVisitor(ast.NodeVisitor):
    """AST visitor with per-function-scope taint propagation AND context
    classification.

    Taint sources: all function parameters (excluding self/cls) and any local
    variable assigned from a tainted expression.

    Context classification: each function is classified as "tool", "safe", or
    "unknown" based on decorators, name, and file path.  Available via
    self._current_context().

    Import alias tracking: `import subprocess as sp` is tracked so that
    `sp.run(...)` is resolved to `subprocess.run(...)` by `_resolve_module`.

    Subclasses should call super().__init__() and implement visit_Call (or
    other sink visitors) while relying on this class for taint and context
    infrastructure.
    """

    def __init__(self) -> None:
        self._param_stack: list[set[str]] = []
        self._tainted_stack: list[set[str]] = []
        self._context_stack: list[str] = []
        # Maps alias → real module name, e.g. "sp" → "subprocess"
        self._import_aliases: dict[str, str] = {}
        # Maps imported name → full qualified name, e.g. "Template" → "jinja2.Template"
        self._from_imports: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Import alias tracking
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        """Track `import X as Y` aliases so `Y.attr()` resolves to `X.attr()`."""
        for alias in node.names:
            if alias.asname:
                self._import_aliases[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track `from X import Y as Z` so `Z` resolves to `X.Y`."""
        module = node.module or ""
        for alias in node.names:
            real_name = f"{module}.{alias.name}" if module else alias.name
            bound_name = alias.asname if alias.asname else alias.name
            self._from_imports[bound_name] = real_name
            # Also store module alias if the whole module is aliased via asname
            if alias.asname:
                self._import_aliases[alias.asname] = real_name
        self.generic_visit(node)

    def _resolve_module(self, name: str) -> str:
        """Return the real module name for an alias, or the name itself."""
        return self._import_aliases.get(name, name)

    # ------------------------------------------------------------------
    # Function scope management
    # ------------------------------------------------------------------

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Push a new scope, traverse the body, then pop."""
        # Classify context before visiting body so visit_Call etc. can query it.
        ctx = self._classify_function(node)
        self._context_stack.append(ctx)

        params: set[str] = {
            arg.arg
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs
            if arg.arg not in ("self", "cls")
        }
        # Include *args and **kwargs — they are also user-controlled.
        if node.args.vararg:
            params.add(node.args.vararg.arg)
        if node.args.kwarg:
            params.add(node.args.kwarg.arg)

        self._param_stack.append(params)
        self._tainted_stack.append(set())
        self.generic_visit(node)
        self._tainted_stack.pop()
        self._param_stack.pop()

        self._context_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    # ------------------------------------------------------------------
    # Context classification
    # ------------------------------------------------------------------

    def _classify_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        """Classify this function as 'tool', 'safe', or 'unknown'.

        Classification order (first match wins):
          1. Special dunder names → safe
          2. Decorator signals → tool or safe
          3. File path directory heuristics → safe
          4. test_ name prefix → safe
          5. Name keyword heuristics → tool
          6. Default → unknown
        """
        if node.name in _SAFE_FUNC_NAMES:
            return "safe"

        for dec in node.decorator_list:
            name = _get_decorator_name(dec)
            if name:
                parts = name.lower().split(".")
                last, first = parts[-1], parts[0]
                if last in _MCP_TOOL_DEC_ENDS:
                    return "tool"
                if first in _CLI_DEC_PREFIXES or last in _CLI_DEC_NAME_ENDS:
                    return "safe"
                if last in _SAFE_SINGLE_DECORATORS:
                    return "safe"

        # File-path heuristics (parent directories only, not filename).
        file_path = getattr(self, "file_path", "")
        if file_path:
            parent_parts = _StdPath(file_path).parts[:-1]
            if any(p in _SAFE_PATH_DIRS for p in parent_parts):
                return "safe"

        if node.name.startswith("test_"):
            return "safe"

        name_lower = node.name.lower()
        if any(kw in name_lower for kw in _TOOL_NAME_KEYWORDS):
            return "tool"

        return "unknown"

    def _current_context(self) -> str:
        """Return the context of the innermost enclosing function, or 'unknown'."""
        return self._context_stack[-1] if self._context_stack else "unknown"

    # ------------------------------------------------------------------
    # Assignment taint propagation
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._tainted_stack and self._is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_stack[-1].add(target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self._tainted_stack and isinstance(node.target, ast.Name):
            if self._is_tainted(node.value) or self._is_tainted(node.target):
                self._tainted_stack[-1].add(node.target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if (
            self._tainted_stack
            and node.value is not None
            and self._is_tainted(node.value)
            and isinstance(node.target, ast.Name)
        ):
            self._tainted_stack[-1].add(node.target.id)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Taint predicate
    # ------------------------------------------------------------------

    def _is_tainted(self, node: ast.expr) -> bool:
        """Return True if the expression contains or propagates a taint source."""
        if isinstance(node, ast.Name):
            return (
                node.id in self._current_params()
                or node.id in self._current_tainted()
            )
        if isinstance(node, ast.JoinedStr):
            # f-strings: check each interpolated expression.
            return any(
                self._is_tainted(fv.value)
                for fv in node.values
                if isinstance(fv, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            # Covers "cmd " + x  and  "cmd %s" % x  (old-style formatting).
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.IfExp):
            # Ternary: x if cond else y — either branch could be tainted.
            return self._is_tainted(node.body) or self._is_tainted(node.orelse)
        if isinstance(node, ast.Subscript):
            # tainted_dict["key"] or tainted_list[i] — propagate from container.
            return self._is_tainted(node.value)
        if isinstance(node, ast.Call):
            # A call whose arguments are tainted is conservatively tainted.
            return (
                any(
                    self._is_tainted(
                        arg.value if isinstance(arg, ast.Starred) else arg
                    )
                    for arg in node.args
                )
                or any(self._is_tainted(kw.value) for kw in node.keywords)
            )
        return False

    def _current_params(self) -> set[str]:
        return self._param_stack[-1] if self._param_stack else set()

    def _current_tainted(self) -> set[str]:
        return self._tainted_stack[-1] if self._tainted_stack else set()

    # ------------------------------------------------------------------
    # AST utilities (available to all subclasses)
    # ------------------------------------------------------------------

    @staticmethod
    def _attr_pair(node: ast.Call) -> tuple[str, str] | None:
        """Extract ('module', 'attr') from module.attr() call patterns.

        Returns the raw names without alias resolution — use
        _resolved_attr_pair for alias-aware matching.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        ):
            return (node.func.value.id, node.func.attr)
        return None

    def _resolved_attr_pair(self, node: ast.Call) -> tuple[str, str] | None:
        """Like _attr_pair but resolves import aliases on the module name.

        E.g. `import subprocess as sp; sp.run(...)` → ('subprocess', 'run').
        """
        pair = self._attr_pair(node)
        if pair is None:
            return None
        return (self._resolve_module(pair[0]), pair[1])

    @staticmethod
    def _attr_triple(node: ast.Call) -> tuple[str, str, str] | None:
        """Extract ('a', 'b', 'c') from a.b.c() call patterns."""
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
        ):
            return (node.func.value.value.id, node.func.value.attr, node.func.attr)
        return None

    def _resolved_attr_triple(self, node: ast.Call) -> tuple[str, str, str] | None:
        """Like _attr_triple but resolves import aliases on the first segment."""
        triple = self._attr_triple(node)
        if triple is None:
            return None
        return (self._resolve_module(triple[0]), triple[1], triple[2])
