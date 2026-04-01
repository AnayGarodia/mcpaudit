"""
Rule: Prompt Injection (MCP-specific)

Detects two high-signal patterns where returning user-influenced data creates
real prompt injection risk. Does NOT flag the normal MCP pattern of "tool takes
parameters and returns a result derived from them."

Pattern 1 — External data passthrough (high risk):
  User-controlled input is used to fetch content from an external source
  (HTTP, file system, subprocess), and that external content is returned
  directly to the LLM. The external source may itself contain attacker-crafted
  instructions (e.g. a webpage or file the attacker controls).

  Examples: requests.get(user_url).text, open(user_path).read(),
            subprocess.check_output(user_cmd)

Pattern 2 — Instruction string injection (medium risk):
  User-controlled input is interpolated into a string whose *static* parts
  contain LLM instruction-like keywords (e.g. "you are", "system:", "act as").
  This directly gives an attacker the ability to embed instructions the LLM
  will follow.

  Example: f"You are {role}. Always respond as {role}."

NOT flagged:
  - Simple echoing:       return f"Hello {name}"
  - Computation results:  return f"Word count: {count}"
  - Error messages:       return f"Error: '{user_input}' is not valid"
  - Fetches with hardcoded URLs/paths (no user-controlled fetch target)
  - Any return where the value is computed from parameters without calling
    an external data source
  - Functions in safe contexts (CLI, utils, auth, classmethod, etc.)

CWE mapping: CWE-020 (Improper Input Validation).
"""
import ast
import re

from mcpaudit.models import Finding
from mcpaudit.rules._taint import TaintVisitor

# External data sources: calls to these functions with user-controlled arguments
# produce content that may contain attacker-injected LLM instructions.
# NOTE: Path() is NOT here — it's path construction, not data fetching.
_FETCH_BUILTINS: frozenset[str] = frozenset({"open"})

_FETCH_PAIRS: frozenset[tuple[str, str]] = frozenset({
    ("requests", "get"), ("requests", "post"), ("requests", "put"),
    ("requests", "delete"), ("requests", "patch"), ("requests", "head"),
    ("requests", "request"),
    ("httpx", "get"), ("httpx", "post"), ("httpx", "put"),
    ("httpx", "delete"), ("httpx", "patch"), ("httpx", "head"),
    ("httpx", "request"),
    ("subprocess", "run"), ("subprocess", "check_output"), ("subprocess", "Popen"),
    ("subprocess", "call"), ("subprocess", "check_call"),
    ("os", "popen"),
})

_FETCH_TRIPLES: frozenset[tuple[str, str, str]] = frozenset({
    ("urllib", "request", "urlopen"),
})

# Keywords in the *static* parts of an f-string that indicate the string is
# being used as an LLM instruction/system-prompt context.
_INSTRUCTION_RE = re.compile(
    r"(?i)(?:"
    r"you are\b|"
    r"your task\b|"
    r"important:|"
    r"system:|"
    r"assistant:|"
    r"ignore previous\b|"
    r"disregard\b|"
    r"act as\b|"
    r"pretend\b|"
    r"from now on\b|"
    r"instructions:|"
    r"roleplay\b"
    r")"
)


def check_prompt_injection(tree: ast.Module, file_path: str = "") -> list[Finding]:
    """Return findings where user input creates real prompt injection risk."""
    visitor = _Visitor(file_path)
    visitor.visit(tree)
    return visitor.findings


class _Visitor(TaintVisitor):
    """
    Extends TaintVisitor with two extra per-scope taint kinds:

    _fetch_tainted  — variables holding the result of an external fetch
                      whose URL/path/command was user-controlled.
    _instruction_tainted — variables holding strings whose static parts
                           look like LLM instructions and whose dynamic
                           parts include user input.
    """

    def __init__(self, file_path: str) -> None:
        super().__init__()
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._fetch_tainted_stack: list[set[str]] = []
        self._instruction_tainted_stack: list[set[str]] = []

    # ------------------------------------------------------------------
    # Scope management — extend TaintVisitor to push/pop extra stacks
    # ------------------------------------------------------------------

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._fetch_tainted_stack.append(set())
        self._instruction_tainted_stack.append(set())
        super()._visit_function(node)   # pushes params/user-taint, visits body, pops
        self._instruction_tainted_stack.pop()
        self._fetch_tainted_stack.pop()

    # ------------------------------------------------------------------
    # Assignment taint propagation — extend TaintVisitor's versions
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        super().visit_Assign(node)
        if self._fetch_tainted_stack and (
            self._is_external_fetch_call(node.value)
            or self._is_fetch_tainted(node.value)
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._fetch_tainted_stack[-1].add(target.id)
        if self._instruction_tainted_stack and self._is_instruction_injection(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._instruction_tainted_stack[-1].add(target.id)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        super().visit_AugAssign(node)
        if isinstance(node.target, ast.Name):
            if self._fetch_tainted_stack and (
                self._is_external_fetch_call(node.value)
                or self._is_fetch_tainted(node.value)
                or self._is_fetch_tainted(node.target)
            ):
                self._fetch_tainted_stack[-1].add(node.target.id)
            if self._instruction_tainted_stack and (
                self._is_instruction_injection(node.value)
                or self._is_instruction_injection(node.target)
            ):
                self._instruction_tainted_stack[-1].add(node.target.id)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        super().visit_AnnAssign(node)
        if node.value is not None and isinstance(node.target, ast.Name):
            if self._fetch_tainted_stack and (
                self._is_external_fetch_call(node.value)
                or self._is_fetch_tainted(node.value)
            ):
                self._fetch_tainted_stack[-1].add(node.target.id)
            if self._instruction_tainted_stack and self._is_instruction_injection(node.value):
                self._instruction_tainted_stack[-1].add(node.target.id)

    # ------------------------------------------------------------------
    # With-statement taint propagation (with open(x) as f / with urlopen(x) as r)
    # ------------------------------------------------------------------

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            if (
                item.optional_vars is not None
                and isinstance(item.optional_vars, ast.Name)
                and self._fetch_tainted_stack
                and self._is_external_fetch_call(item.context_expr)
            ):
                self._fetch_tainted_stack[-1].add(item.optional_vars.id)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    # ------------------------------------------------------------------
    # Sink detection
    # ------------------------------------------------------------------

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            ctx = self._current_context()
            if ctx != "safe":
                if self._is_external_fetch_call(node.value) or self._is_fetch_tainted(node.value):
                    self._report_fetch(node)
                elif self._is_instruction_injection(node.value):
                    self._report_instruction(node)
        self.generic_visit(node)

    def _report_fetch(self, node: ast.Return) -> None:
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity="medium",
            cwe_id="CWE-020",
            rule_id="prompt_injection",
            description=(
                "User-controlled input is used to fetch external content (file, HTTP, or "
                "subprocess) that is returned directly to the LLM; the external source "
                "may contain attacker-injected instructions."
            ),
            remediation=(
                "Validate and allowlist the URL/path/command before fetching. "
                "Wrap fetched content in a clearly delimited block "
                "(e.g. <external_content>...</external_content>) and instruct the LLM "
                "to treat it as data, not instructions."
            ),
        ))

    def _report_instruction(self, node: ast.Return) -> None:
        self.findings.append(Finding(
            file_path=self.file_path,
            line=node.lineno,
            severity="medium",
            cwe_id="CWE-020",
            rule_id="prompt_injection",
            description=(
                "User-controlled input is interpolated into a string whose static parts "
                "contain LLM instruction-like keywords; an attacker can embed instructions "
                "the LLM will follow."
            ),
            remediation=(
                "Keep system prompts fully static. Do not construct instruction strings "
                "from user input. If user content must appear alongside instructions, "
                "wrap it in a clearly delimited data block."
            ),
        ))

    # ------------------------------------------------------------------
    # Fetch-taint predicate
    # ------------------------------------------------------------------

    def _is_external_fetch_call(self, node: ast.expr) -> bool:
        """True if node is a call to an external data source with user-tainted args."""
        if not isinstance(node, ast.Call):
            return False
        has_tainted_arg = any(
            self._is_tainted(arg.value if isinstance(arg, ast.Starred) else arg)
            for arg in node.args
        ) or any(self._is_tainted(kw.value) for kw in node.keywords)
        if not has_tainted_arg:
            return False
        func = node.func
        if isinstance(func, ast.Name) and func.id in _FETCH_BUILTINS:
            return True
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if (func.value.id, func.attr) in _FETCH_PAIRS:
                return True
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
        ):
            triple = (func.value.value.id, func.value.attr, func.attr)
            if triple in _FETCH_TRIPLES:
                return True
        return False

    def _is_fetch_tainted(self, node: ast.expr) -> bool:
        """True if node is or wraps a fetch-tainted value."""
        fetch_set = self._fetch_tainted_stack[-1] if self._fetch_tainted_stack else set()
        if isinstance(node, ast.Name):
            return node.id in fetch_set
        # response.text, result.stdout, file_obj.name — attribute on fetch-tainted object
        if isinstance(node, ast.Attribute):
            return self._is_fetch_tainted(node.value)
        if isinstance(node, ast.Call):
            if self._is_external_fetch_call(node):
                return True
            # Method call on fetch-tainted object: response.json(), data.decode(), f.read()
            if isinstance(node.func, ast.Attribute):
                return self._is_fetch_tainted(node.func.value)
            return False
        if isinstance(node, ast.JoinedStr):
            return any(
                self._is_fetch_tainted(fv.value)
                for fv in node.values
                if isinstance(fv, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_fetch_tainted(node.left) or self._is_fetch_tainted(node.right)
        return False

    # ------------------------------------------------------------------
    # Instruction-injection predicate
    # ------------------------------------------------------------------

    def _is_instruction_injection(self, node: ast.expr) -> bool:
        """True if node contains user input interpolated into instruction-like text."""
        instruction_set = (
            self._instruction_tainted_stack[-1] if self._instruction_tainted_stack else set()
        )
        if isinstance(node, ast.Name):
            return node.id in instruction_set

        if isinstance(node, ast.JoinedStr):
            has_user_taint = any(
                self._is_tainted(fv.value)
                for fv in node.values
                if isinstance(fv, ast.FormattedValue)
            )
            if not has_user_taint:
                return False
            static_text = "".join(
                c.value
                for c in node.values
                if isinstance(c, ast.Constant) and isinstance(c.value, str)
            )
            return bool(_INSTRUCTION_RE.search(static_text))

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if (
                isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and bool(_INSTRUCTION_RE.search(node.left.value))
                and self._is_tainted(node.right)
            ):
                return True
            if (
                isinstance(node.right, ast.Constant)
                and isinstance(node.right.value, str)
                and bool(_INSTRUCTION_RE.search(node.right.value))
                and self._is_tainted(node.left)
            ):
                return True
            return (
                self._is_instruction_injection(node.left)
                or self._is_instruction_injection(node.right)
            )

        return False
