"""Orchestrates rules against one or more Python source files."""
import ast
import fnmatch
from pathlib import Path

from mcpaudit.models import Finding
from mcpaudit.rules.code_injection import check_code_injection
from mcpaudit.rules.hardcoded_secrets import check_hardcoded_secrets
from mcpaudit.rules.path_traversal import check_path_traversal
from mcpaudit.rules.prompt_injection import check_prompt_injection
from mcpaudit.rules.shell_injection import check_shell_injection
from mcpaudit.rules.sql_injection import check_sql_injection
from mcpaudit.rules.ssrf import check_ssrf
from mcpaudit.rules.unsafe_deserialization import check_unsafe_deserialization

# All registered rules. Each takes (ast.Module, file_path) -> list[Finding].
_RULES = [
    check_shell_injection,
    check_code_injection,
    check_sql_injection,
    check_path_traversal,
    check_ssrf,
    check_hardcoded_secrets,
    check_prompt_injection,
    check_unsafe_deserialization,
]

# Default glob patterns excluded when scanning a directory.
# These represent test/fixture code that is almost never itself vulnerable to the
# classes of attack mcpaudit looks for (path traversal, shell injection, etc.).
# Users can disable these with --no-default-excludes, or add more with --exclude.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "**/test_*.py",   # unittest/pytest test files
    "**/tests/**",    # anything inside a tests/ directory
    "**/*_test.py",   # test files suffixed with _test
    "**/testing/**",  # anything inside a testing/ directory
    "**/conftest.py", # pytest configuration/fixture files
)


def _is_excluded(file_path: Path, patterns: tuple[str, ...]) -> bool:
    """Return True if file_path matches any of the given glob-style exclude patterns.

    Supports three pattern forms:
      **/dirname/**   — matches if dirname is any component in the path
      **/suffix       — matches if the filename matches the suffix pattern
      other           — fnmatch against the full posix path or just the filename
    """
    if not patterns:
        return False

    posix = file_path.as_posix()
    name = file_path.name
    # Set of all path components (including filename) for fast membership tests.
    parts_set = set(file_path.parts)

    for pat in patterns:
        pat = pat.replace("\\", "/")
        if pat.startswith("**/") and pat.endswith("/**"):
            # e.g. **/tests/** — true if any path component equals the middle segment
            component = pat[3:-3]
            if component in parts_set:
                return True
        elif pat.startswith("**/"):
            # e.g. **/test_*.py — match just the filename against the tail pattern
            tail = pat[3:]
            if fnmatch.fnmatch(name, tail):
                return True
        else:
            # No **: direct fnmatch on full path or filename
            if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(name, pat):
                return True

    return False


def scan_file(
    path: Path,
    rule_filter: set[str] | None = None,
) -> tuple[list[Finding], str | None]:
    """Parse a single Python file and run all rules against it.

    Args:
        path:        File to scan.
        rule_filter: If provided, only run rules whose rule_id is in this set.

    Returns (findings, error). error is None on success, or a message when the
    file was skipped (unreadable, bad encoding, syntax error).
    """
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [], f"{path}: could not read file ({exc})"

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [], f"{path}: syntax error ({exc})"

    lines = source.splitlines()

    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(tree, str(path)))

    # Populate snippet from source and apply inline suppression comments.
    result: list[Finding] = []
    for f in findings:
        if rule_filter is not None and f.rule_id and f.rule_id not in rule_filter:
            continue
        if 0 < f.line <= len(lines):
            f.snippet = lines[f.line - 1].strip()
            line_text = lines[f.line - 1]
            # Honour "# mcpaudit: ignore" and "# mcpaudit: ignore[CWE-XX]"
            if "# mcpaudit: ignore" in line_text:
                # Check for CWE-specific suppression
                tag = f"# mcpaudit: ignore[{f.cwe_id}]"
                generic = "# mcpaudit: ignore"
                # Accept both the generic form and the CWE-specific form.
                if tag in line_text or (
                    generic in line_text and f"# mcpaudit: ignore[" not in line_text
                ):
                    continue
        result.append(f)
    return result, None


def scan_path(
    target: Path,
    excludes: tuple[str, ...] = (),
    rule_filter: set[str] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Scan a file or recursively scan a directory for Python files.

    Args:
        target:      File or directory to scan.
        excludes:    Glob patterns for files to skip.
        rule_filter: If provided, only run rules whose rule_id is in this set.

    Returns (findings, skipped) where skipped is a list of human-readable
    messages for files that could not be parsed.
    """
    if target.is_file():
        if _is_excluded(target, excludes):
            return [], []
        findings, error = scan_file(target, rule_filter=rule_filter)
        return findings, ([error] if error else [])

    findings: list[Finding] = []
    skipped: list[str] = []
    for py_file in sorted(target.rglob("*.py")):
        if _is_excluded(py_file, excludes):
            continue
        file_findings, error = scan_file(py_file, rule_filter=rule_filter)
        findings.extend(file_findings)
        if error:
            skipped.append(error)
    return findings, skipped
