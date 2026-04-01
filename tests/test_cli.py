"""Tests for the CLI output formats and options."""
import json
from pathlib import Path

from click.testing import CliRunner

from mcpaudit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_text_output_shows_findings() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--no-default-excludes",
    ])
    assert result.exit_code == 1
    assert "CWE-78" in result.output
    assert "finding" in result.output.lower()


def test_text_output_no_findings_exit_0(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text('def greet(name: str) -> str:\n    return f"Hello, {name}"\n')
    runner = CliRunner()
    result = runner.invoke(main, [str(clean)])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_json_output_valid() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
    ])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) > 0
    assert all("cwe_id" in f for f in data)
    assert all("severity" in f for f in data)
    assert all("line" in f for f in data)


def test_json_output_empty_when_clean(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text('def greet(name: str) -> str:\n    return f"Hello, {name}"\n')
    runner = CliRunner()
    result = runner.invoke(main, [str(clean), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data == []


def test_sarif_output_valid() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "sarif",
        "--no-default-excludes",
    ])
    assert result.exit_code == 1
    sarif = json.loads(result.output)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpaudit"
    assert len(run["results"]) > 0


def test_sarif_output_empty_when_clean(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text('def greet(name: str) -> str:\n    return f"Hello, {name}"\n')
    runner = CliRunner()
    result = runner.invoke(main, [str(clean), "--format", "sarif"])
    assert result.exit_code == 0
    sarif = json.loads(result.output)
    assert sarif["runs"][0]["results"] == []


def test_min_severity_filters() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--min-severity", "critical",
        "--no-default-excludes",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data == []


def test_no_exit_code_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--no-exit-code",
        "--no-default-excludes",
    ])
    assert result.exit_code == 0


def test_exclude_option() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
        "--exclude", "**/shell_injection_vulnerable.py",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data == []


def test_no_default_excludes() -> None:
    runner = CliRunner()
    # With default excludes, test files are skipped.
    # With --no-default-excludes, they should be scanned.
    result = runner.invoke(main, [
        str(FIXTURES),
        "--format", "json",
        "--no-default-excludes",
    ])
    data = json.loads(result.output)
    assert len(data) > 0


def test_scan_directory() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES),
        "--format", "json",
        "--no-default-excludes",
    ])
    assert result.exit_code == 1
    data = json.loads(result.output)
    # Should find findings across multiple fixture files
    cwe_ids = {f["cwe_id"] for f in data}
    assert len(cwe_ids) >= 2  # At least 2 different CWE types


def test_json_includes_rule_id() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
    ])
    data = json.loads(result.output)
    assert all("rule_id" in f for f in data)
    shell = [f for f in data if f["cwe_id"] == "CWE-78"]
    assert all(f["rule_id"] == "shell_injection" for f in shell)


def test_json_includes_snippet() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
    ])
    data = json.loads(result.output)
    assert all("snippet" in f for f in data)
    shell = [f for f in data if f["cwe_id"] == "CWE-78"]
    assert any(f["snippet"] for f in shell)


def test_output_file_json(tmp_path: Path) -> None:
    out = tmp_path / "results.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
        "--output-file", str(out),
    ])
    assert result.exit_code == 1
    assert out.exists()
    data = json.loads(out.read_text())
    assert isinstance(data, list)
    assert len(data) > 0


def test_output_file_sarif(tmp_path: Path) -> None:
    out = tmp_path / "results.sarif"
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "sarif",
        "--no-default-excludes",
        "--output-file", str(out),
    ])
    assert result.exit_code == 1
    assert out.exists()
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"


def test_rules_filter() -> None:
    runner = CliRunner()
    # Only run path_traversal — should get 0 findings from shell injection fixture
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
        "--rules", "path_traversal",
    ])
    data = json.loads(result.output)
    shell = [f for f in data if f["cwe_id"] == "CWE-78"]
    assert shell == []


def test_rules_filter_correct_rule_found() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "json",
        "--no-default-excludes",
        "--rules", "shell_injection",
    ])
    data = json.loads(result.output)
    assert len(data) > 0
    assert all(f["rule_id"] == "shell_injection" for f in data)


def test_text_output_shows_summary_stats() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--no-default-excludes",
    ])
    assert "finding" in result.output.lower()
    # Summary should contain severity labels
    assert "high" in result.output or "medium" in result.output


def test_sarif_uses_rule_id_in_results() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        str(FIXTURES / "shell_injection_vulnerable.py"),
        "--format", "sarif",
        "--no-default-excludes",
    ])
    sarif = json.loads(result.output)
    results = sarif["runs"][0]["results"]
    assert all("ruleId" in r for r in results)
    shell = [r for r in results if r["ruleId"] == "shell_injection"]
    assert len(shell) > 0
