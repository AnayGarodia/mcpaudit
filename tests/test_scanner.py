"""Tests for the scanner module — file exclusion and orchestration."""
import ast
from pathlib import Path

from mcpaudit.scanner import _is_excluded, scan_file, scan_path, DEFAULT_EXCLUDES

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# _is_excluded — pattern matching
# ---------------------------------------------------------------------------

class TestIsExcluded:
    """Tests for the _is_excluded helper."""

    def test_no_patterns_never_excludes(self) -> None:
        assert _is_excluded(Path("src/foo.py"), ()) is False

    # **/dirname/** patterns
    def test_dir_pattern_matches_component(self) -> None:
        assert _is_excluded(Path("src/tests/test_foo.py"), ("**/tests/**",)) is True

    def test_dir_pattern_no_match(self) -> None:
        assert _is_excluded(Path("src/main.py"), ("**/tests/**",)) is False

    def test_dir_pattern_nested(self) -> None:
        assert _is_excluded(Path("a/b/tests/c/d.py"), ("**/tests/**",)) is True

    # **/suffix patterns
    def test_suffix_pattern_matches_filename(self) -> None:
        assert _is_excluded(Path("src/test_foo.py"), ("**/test_*.py",)) is True

    def test_suffix_pattern_no_match(self) -> None:
        assert _is_excluded(Path("src/foo.py"), ("**/test_*.py",)) is False

    def test_suffix_conftest(self) -> None:
        assert _is_excluded(Path("tests/conftest.py"), ("**/conftest.py",)) is True

    def test_suffix_test_suffix(self) -> None:
        assert _is_excluded(Path("src/foo_test.py"), ("**/*_test.py",)) is True

    # plain patterns
    def test_plain_glob_on_filename(self) -> None:
        assert _is_excluded(Path("foo.pyc"), ("*.pyc",)) is True

    def test_plain_glob_no_match(self) -> None:
        assert _is_excluded(Path("foo.py"), ("*.pyc",)) is False

    # testing/** pattern
    def test_testing_dir_excluded(self) -> None:
        assert _is_excluded(Path("lib/testing/helpers.py"), ("**/testing/**",)) is True


# ---------------------------------------------------------------------------
# DEFAULT_EXCLUDES — each pattern works
# ---------------------------------------------------------------------------

class TestDefaultExcludes:
    """Verify each DEFAULT_EXCLUDES pattern catches its target."""

    def test_test_file_prefix(self) -> None:
        assert _is_excluded(Path("src/test_server.py"), DEFAULT_EXCLUDES) is True

    def test_tests_directory(self) -> None:
        assert _is_excluded(Path("project/tests/test_foo.py"), DEFAULT_EXCLUDES) is True

    def test_test_file_suffix(self) -> None:
        assert _is_excluded(Path("src/server_test.py"), DEFAULT_EXCLUDES) is True

    def test_testing_directory(self) -> None:
        assert _is_excluded(Path("project/testing/helpers.py"), DEFAULT_EXCLUDES) is True

    def test_conftest(self) -> None:
        assert _is_excluded(Path("tests/conftest.py"), DEFAULT_EXCLUDES) is True

    def test_regular_file_not_excluded(self) -> None:
        assert _is_excluded(Path("src/server.py"), DEFAULT_EXCLUDES) is False

    def test_fixture_not_excluded_by_default(self) -> None:
        """Fixture files are inside tests/ dir, so they ARE excluded by default."""
        assert _is_excluded(Path("tests/fixtures/vuln.py"), DEFAULT_EXCLUDES) is True


# ---------------------------------------------------------------------------
# scan_file — basic parsing and rule execution
# ---------------------------------------------------------------------------

class TestScanFile:
    def test_scan_vulnerable_file(self) -> None:
        findings, error = scan_file(FIXTURES / "shell_injection_vulnerable.py")
        assert error is None
        assert len(findings) > 0

    def test_scan_safe_file(self) -> None:
        findings, error = scan_file(FIXTURES / "shell_injection_safe.py")
        assert error is None
        # Safe files may still trigger other rules (e.g., path traversal for open())
        # but should not trigger shell injection specifically
        shell_findings = [f for f in findings if f.cwe_id == "CWE-78"]
        assert shell_findings == []

    def test_scan_nonexistent_file(self) -> None:
        findings, error = scan_file(Path("/nonexistent/file.py"))
        assert findings == []
        assert error is not None
        assert "could not read" in error

    def test_scan_syntax_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("def broken(:\n")
        findings, error = scan_file(bad)
        assert findings == []
        assert error is not None
        assert "syntax error" in error


# ---------------------------------------------------------------------------
# scan_path — directory scanning with excludes
# ---------------------------------------------------------------------------

class TestScanPath:
    def test_scan_single_file(self) -> None:
        findings, skipped = scan_path(FIXTURES / "shell_injection_vulnerable.py")
        assert len(findings) > 0
        assert skipped == []

    def test_scan_directory(self) -> None:
        findings, skipped = scan_path(FIXTURES)
        assert len(findings) > 0

    def test_exclude_skips_file(self, tmp_path: Path) -> None:
        vuln = tmp_path / "test_vuln.py"
        vuln.write_text('import os\ndef run(cmd: str): os.system(cmd)\n')
        findings, _ = scan_path(tmp_path, excludes=("**/test_*.py",))
        assert findings == []

    def test_exclude_single_file_target(self, tmp_path: Path) -> None:
        vuln = tmp_path / "test_vuln.py"
        vuln.write_text('import os\ndef run(cmd: str): os.system(cmd)\n')
        findings, _ = scan_path(vuln, excludes=("**/test_*.py",))
        assert findings == []

    def test_no_excludes_finds_everything(self) -> None:
        findings, _ = scan_path(FIXTURES, excludes=())
        assert len(findings) > 0


# ---------------------------------------------------------------------------
# snippet population and suppression
# ---------------------------------------------------------------------------

class TestSnippetAndSuppression:
    def test_snippet_is_populated(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f)
        shell = [x for x in findings if x.cwe_id == "CWE-78"]
        assert shell
        assert shell[0].snippet != ""
        assert "os.system" in shell[0].snippet

    def test_suppression_generic(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)  # mcpaudit: ignore\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f)
        shell = [x for x in findings if x.cwe_id == "CWE-78"]
        assert shell == []

    def test_suppression_cwe_specific(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)  # mcpaudit: ignore[CWE-78]\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f)
        shell = [x for x in findings if x.cwe_id == "CWE-78"]
        assert shell == []

    def test_suppression_cwe_specific_different_cwe_not_suppressed(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)  # mcpaudit: ignore[CWE-22]\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f)
        shell = [x for x in findings if x.cwe_id == "CWE-78"]
        assert shell  # CWE-78 NOT suppressed by CWE-22 tag

    def test_rule_id_populated(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f)
        shell = [x for x in findings if x.cwe_id == "CWE-78"]
        assert shell[0].rule_id == "shell_injection"


class TestRuleFilter:
    def test_rule_filter_includes_matching(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f, rule_filter={"shell_injection"})
        assert any(x.cwe_id == "CWE-78" for x in findings)

    def test_rule_filter_excludes_non_matching(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f, rule_filter={"path_traversal"})
        shell = [x for x in findings if x.cwe_id == "CWE-78"]
        assert shell == []

    def test_rule_filter_none_runs_all(self, tmp_path: Path) -> None:
        src = "def run(cmd: str):\n    import os\n    os.system(cmd)\n"
        f = tmp_path / "vuln.py"
        f.write_text(src)
        findings, _ = scan_file(f, rule_filter=None)
        assert any(x.cwe_id == "CWE-78" for x in findings)
