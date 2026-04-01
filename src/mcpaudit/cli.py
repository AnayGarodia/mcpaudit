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
        if f.cwe_id not in seen_rules:
            cwe_num = f.cwe_id.split("-")[-1]
            seen_rules[f.cwe_id] = {
                "id": f.cwe_id,
                "name": f.cwe_id.replace("-", ""),
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "shortDescription": {"text": f.cwe_id},
            }

    results = [
        {
            "ruleId": f.cwe_id,
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
def main(
    path: Path,
    min_severity: str,
    exit_code: bool,
    output_format: str,
    extra_excludes: tuple[str, ...],
    no_default_excludes: bool,
) -> None:
    """Scan a Python file or directory for MCP server security vulnerabilities."""
    excludes: tuple[str, ...] = () if no_default_excludes else DEFAULT_EXCLUDES
    excludes = excludes + extra_excludes
    findings, skipped = scan_path(path, excludes=excludes)

    order = ["low", "medium", "high", "critical"]
    min_idx = order.index(min_severity)
    findings = [f for f in findings if order.index(f.severity) >= min_idx]

    if output_format == "json":
        print(_format_json(findings))
        if exit_code and findings:
            sys.exit(1)
        sys.exit(0)

    if output_format == "sarif":
        print(_format_sarif(findings))
        if exit_code and findings:
            sys.exit(1)
        sys.exit(0)

    # Text output (default)
    console = Console(theme=_THEME)
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
        body = (
            f"[bold]Description:[/bold] {f.description}\n"
            f"[bold]Remediation:[/bold] {f.remediation}"
        )
        color = _SEVERITY_COLOR.get(f.severity, "white")
        console.print(Panel(body, title=header, border_style=color, title_align="left"))

    count = len(findings)
    console.print(f"[warning]{count} finding{'s' if count != 1 else ''} found.[/warning]\n")

    if exit_code:
        sys.exit(1)
