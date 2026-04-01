"""CLI entry point for mcpaudit."""
import json
import sys
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

from mcpaudit.models import Finding
from mcpaudit.scanner import DEFAULT_EXCLUDES, scan_path

# Map severity → sort order for summary
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]

try:
    _VERSION = version("mcpaudit")
except PackageNotFoundError:
    _VERSION = "0.1.0"

_SEVERITY_COLOR = {
    "low": "yellow",
    "medium": "dark_orange",
    "high": "red",
    "critical": "bold red",
}

_SARIF_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

_THEME = Theme({"info": "dim cyan", "success": "green", "warning": "yellow"})


def _severity_badge(severity: str) -> Text:
    color = _SEVERITY_COLOR.get(severity, "white")
    return Text(f" {severity.upper()} ", style=f"bold white on {color}")


def _format_json(findings: list[Finding]) -> str:
    """Serialize findings to a JSON array."""
    return json.dumps([asdict(f) for f in findings], indent=2)


def _format_sarif(findings: list[Finding]) -> str:
    """Serialize findings to SARIF 2.1.0 format."""
    seen_rules: dict[str, dict] = {}
    for f in findings:
        rule_key = f.rule_id if f.rule_id else f.cwe_id
        if rule_key not in seen_rules:
            cwe_num = f.cwe_id.split("-")[-1]
            seen_rules[rule_key] = {
                "id": rule_key,
                "name": rule_key.replace("_", " ").title().replace(" ", ""),
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "shortDescription": {"text": f"{f.cwe_id} — {rule_key}"},
            }

    results = [
        {
            "ruleId": f.rule_id if f.rule_id else f.cwe_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line},
                }
            }],
        }
        for f in findings
    ]

    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcpaudit",
                    "version": _VERSION,
                    "rules": list(seen_rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--min-severity", default="low",
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Only show findings at or above this severity.")
@click.option("--exit-code/--no-exit-code", default=True,
              help="Exit with code 1 when findings are present (default: on).")
@click.option("--format", "output_format", default="text",
              type=click.Choice(["text", "json", "sarif"]),
              help="Output format: text (default), json, or sarif.")
@click.option("--exclude", "extra_excludes", multiple=True, metavar="GLOB",
              help="Additional glob patterns to exclude (e.g. '**/generated/**'). "
                   "Can be specified multiple times.")
@click.option("--no-default-excludes", is_flag=True, default=False,
              help="Disable the default test-file exclusions "
                   f"({', '.join(DEFAULT_EXCLUDES)}).")
@click.option("--output-file", "output_file", default=None,
              type=click.Path(writable=True),
              help="Write output to a file instead of stdout.")
@click.option("--rules", "rules_filter", default=None,
              help="Comma-separated rule IDs to run "
                   "(e.g. shell_injection,path_traversal). Default: all rules.")
def main(
    path: Path,
    min_severity: str,
    exit_code: bool,
    output_format: str,
    extra_excludes: tuple[str, ...],
    no_default_excludes: bool,
    output_file: str | None,
    rules_filter: str | None,
) -> None:
    """Scan a Python file or directory for MCP server security vulnerabilities."""
    excludes: tuple[str, ...] = () if no_default_excludes else DEFAULT_EXCLUDES
    excludes = excludes + extra_excludes

    rule_filter: set[str] | None = None
    if rules_filter:
        rule_filter = {r.strip() for r in rules_filter.split(",") if r.strip()}

    findings, skipped = scan_path(path, excludes=excludes, rule_filter=rule_filter)

    order = _SEVERITY_ORDER
    min_idx = order.index(min_severity)
    findings = [f for f in findings if order.index(f.severity) >= min_idx]

    if output_format == "json":
        output = _format_json(findings)
        _write_output(output, output_file)
        if exit_code and findings:
            sys.exit(1)
        sys.exit(0)

    if output_format == "sarif":
        output = _format_sarif(findings)
        _write_output(output, output_file)
        if exit_code and findings:
            sys.exit(1)
        sys.exit(0)

    # Text output (default)
    _render_text(findings, skipped, path, order, output_file, exit_code)


def _render_text(
    findings: list[Finding],
    skipped: list[str],
    path: Path,
    order: list[str],
    output_file: str | None,
    exit_code: bool,
) -> None:
    """Render findings as rich text output to stdout or a file."""
    out_fh = open(output_file, "w", encoding="utf-8") if output_file else None
    try:
        console = Console(theme=_THEME, file=out_fh)
        console.print(f"\n[info]mcpaudit[/info] scanning [bold]{path}[/bold]\n")

        for msg in skipped:
            console.print(f"[warning]skipped:[/warning] {msg}")
        if skipped:
            console.print()

        if not findings:
            console.print("[success]No findings.[/success]\n")
            sys.exit(0)

        for f in findings:
            badge = _severity_badge(f.severity)
            header = Text.assemble(badge, f"  {f.cwe_id}  {f.file_path}:{f.line}")
            body_parts = [
                f"[bold]Description:[/bold] {f.description}",
                f"[bold]Remediation:[/bold] {f.remediation}",
            ]
            if f.snippet:
                body_parts.append(f"[dim italic]{f.snippet}[/dim italic]")
            body = "\n".join(body_parts)
            color = _SEVERITY_COLOR.get(f.severity, "white")
            console.print(Panel(body, title=header, border_style=color, title_align="left"))

        count = len(findings)
        # Summary breakdown by severity
        counts_by_sev = {s: sum(1 for f in findings if f.severity == s) for s in order}
        parts = [
            f"[bold]{counts_by_sev[s]}[/bold] {s}"
            for s in order
            if counts_by_sev[s] > 0
        ]
        summary = "  ·  ".join(parts)
        console.print(
            f"[warning]{count} finding{'s' if count != 1 else ''} found:[/warning]  {summary}\n"
        )
    finally:
        if out_fh is not None:
            out_fh.close()

    if exit_code and findings:
        sys.exit(1)


def _write_output(text: str, output_file: str | None) -> None:
    """Write text to a file or stdout."""
    if output_file:
        Path(output_file).write_text(text, encoding="utf-8")
    else:
        print(text)
