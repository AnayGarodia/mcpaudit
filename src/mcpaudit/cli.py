"""CLI entry point for mcpaudit."""
import json
import sys
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.theme import Theme

from mcpaudit.models import Finding
from mcpaudit.scanner import DEFAULT_EXCLUDES, scan_file, scan_path

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


# ---------------------------------------------------------------------------
# Config file support (.mcpaudit.toml)
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load .mcpaudit.toml from the current working directory.

    Returns an empty dict if no config file is found or cannot be parsed.
    """
    config_path = Path.cwd() / ".mcpaudit.toml"
    if not config_path.exists():
        return {}

    try:
        if sys.version_info >= (3, 11):
            import tomllib  # type: ignore[import]
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        else:
            try:
                import tomli  # type: ignore[import]
                data = tomli.loads(config_path.read_text(encoding="utf-8"))
            except ImportError:
                return {}
        return data.get("mcpaudit", {})
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# Baseline support
# ---------------------------------------------------------------------------

def _baseline_key(f: Finding, scan_root: Path) -> tuple:
    """Stable identity key for a finding, with file_path normalized relative to scan_root.

    Using a relative path ensures the baseline is portable across machines and
    directory layouts — two developers cloning the repo to different paths will
    produce identical keys for the same findings.
    """
    try:
        rel = Path(f.file_path).resolve().relative_to(scan_root.resolve())
        rel_str = str(rel)
    except ValueError:
        rel_str = f.file_path  # fallback if path is outside scan root
    return (rel_str, f.line, f.rule_id, f.cwe_id)


def _load_baseline(path: str) -> set[tuple]:
    """Load a baseline JSON file and return a set of finding identity tuples."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {
            (item["file_path"], item["line"], item["rule_id"], item["cwe_id"])
            for item in data
            if all(k in item for k in ("file_path", "line", "rule_id", "cwe_id"))
        }
    except Exception:  # noqa: BLE001
        return set()


def _save_baseline(findings: list[Finding], path: str, scan_root: Path) -> None:
    """Write findings as JSON to the baseline file, with relative file paths."""
    portable: list[dict] = []
    for f in findings:
        d = {
            "file_path": str(
                Path(f.file_path).resolve().relative_to(scan_root.resolve())
                if Path(f.file_path).is_absolute() or Path(f.file_path).exists()
                else Path(f.file_path)
            ),
            "line": f.line,
            "rule_id": f.rule_id,
            "cwe_id": f.cwe_id,
            "severity": f.severity,
            "description": f.description,
        }
        portable.append(d)
    Path(path).write_text(json.dumps(portable, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Custom Group class that routes to scan command unless first arg is a subcommand
# ---------------------------------------------------------------------------

#: Known subcommand names — any other first token is treated as PATH for scan.
_KNOWN_SUBCOMMANDS: frozenset[str] = frozenset({"init", "scan"})


class _ScanGroup(click.Group):
    """A click Group that invokes the 'scan' subcommand by default.

    When the first non-option argument is not a known subcommand, all args are
    forwarded to the embedded scan command so that ``mcpaudit path/ --opts``
    works identically to ``mcpaudit scan path/ --opts``.
    """

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        # Peek at the first non-option argument.
        first_non_opt = next(
            (a for a in args if not a.startswith("-") and a != "--"), None
        )
        if first_non_opt is not None and first_non_opt not in _KNOWN_SUBCOMMANDS:
            # Treat as default scan: store raw args for invoke() to pass through.
            ctx.ensure_object(dict)
            ctx.obj = ctx.obj or {}
            ctx.obj["_default_scan_args"] = args
            ctx.args = []
            return []
        return super().parse_args(ctx, args)

    def invoke(self, ctx: click.Context) -> object:
        scan_args = (ctx.obj or {}).get("_default_scan_args")
        if scan_args is not None:
            # Invoke the scan subcommand with the original args.
            cmd = self.get_command(ctx, "scan")
            assert cmd is not None
            with cmd.make_context(
                "mcpaudit",
                list(scan_args),
                parent=ctx,
                allow_extra_args=False,
                allow_interspersed_args=True,
            ) as sub_ctx:
                return cmd.invoke(sub_ctx)
        return super().invoke(ctx)


# ---------------------------------------------------------------------------
# Scan subcommand
# ---------------------------------------------------------------------------

@click.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--min-severity", default=None,
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Only show findings at or above this severity.")
@click.option("--exit-code/--no-exit-code", default=True,
              help="Exit with code 1 when findings are present (default: on).")
@click.option("--format", "output_format", default=None,
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
@click.option("--baseline", "baseline_file", default=None,
              type=click.Path(),
              help="Path to baseline JSON file. On first run, saves findings. "
                   "On subsequent runs, only reports new findings.")
def _scan(
    path: Path,
    min_severity: str | None,
    exit_code: bool,
    output_format: str | None,
    extra_excludes: tuple[str, ...],
    no_default_excludes: bool,
    output_file: str | None,
    rules_filter: str | None,
    baseline_file: str | None,
) -> None:
    """Scan a Python file or directory for MCP server security vulnerabilities."""
    # Merge config file defaults (CLI flags override via None sentinels).
    cfg = _load_config()
    if min_severity is None:
        min_severity = cfg.get("min_severity", "low")
    if output_format is None:
        output_format = cfg.get("format", "text")
    cfg_excludes = tuple(cfg.get("exclude", []))
    extra_excludes = extra_excludes + cfg_excludes
    if rules_filter is None and cfg.get("rules"):
        rules_filter = ",".join(cfg["rules"])

    excludes: tuple[str, ...] = () if no_default_excludes else DEFAULT_EXCLUDES
    excludes = excludes + extra_excludes

    rule_filter: set[str] | None = None
    if rules_filter:
        rule_filter = {r.strip() for r in rules_filter.split(",") if r.strip()}

    # Determine if we should show a progress bar.
    show_progress = (output_format == "text") and path.is_dir() and output_file is None

    if show_progress:
        from mcpaudit.scanner import _is_excluded
        all_py = sorted(path.rglob("*.py"))
        py_files = [f for f in all_py if not _is_excluded(f, excludes)]
        total = len(py_files)

        findings: list[Finding] = []
        skipped: list[str] = []

        stderr_console = Console(theme=_THEME, stderr=True)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=stderr_console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning...", total=total)
            for py_file in py_files:
                progress.update(task, description=f"[dim]{py_file.name}[/dim]")
                file_findings, error = scan_file(py_file, rule_filter=rule_filter)
                findings.extend(file_findings)
                if error:
                    skipped.append(error)
                progress.advance(task)
    else:
        findings, skipped = scan_path(path, excludes=excludes, rule_filter=rule_filter)

    order = _SEVERITY_ORDER
    min_idx = order.index(min_severity)
    findings = [f for f in findings if order.index(f.severity) >= min_idx]

    # Baseline logic.
    scan_root = path if path.is_dir() else path.parent
    if baseline_file is not None:
        baseline_path = Path(baseline_file)
        if not baseline_path.exists():
            # First run: save and exit 0.
            _save_baseline(findings, baseline_file, scan_root)
            click.echo(f"Baseline saved to {baseline_file} ({len(findings)} findings).")
            sys.exit(0)

        baseline_keys = _load_baseline(baseline_file)
        new_findings = [f for f in findings if _baseline_key(f, scan_root) not in baseline_keys]
        suppressed = len(findings) - len(new_findings)
        if output_format not in ("json", "sarif") and suppressed > 0:
            click.echo(
                f"Baseline: {len(new_findings)} new finding(s) "
                f"({suppressed} suppressed by baseline).",
                err=True,
            )
        findings = new_findings

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


# ---------------------------------------------------------------------------
# Init subcommand
# ---------------------------------------------------------------------------

@click.command("init")
def _init() -> None:
    """Generate a .mcpaudit.toml config file in the current directory."""
    config_path = Path.cwd() / ".mcpaudit.toml"
    if config_path.exists():
        click.echo(f".mcpaudit.toml already exists at {config_path}")
        click.echo("Remove it first if you want to regenerate.")
        sys.exit(1)

    content = """\
[mcpaudit]
min_severity = "low"
format = "text"
exclude = [
    "**/generated/**",
    "**/vendor/**",
]
rules = []   # empty = all rules
"""
    config_path.write_text(content, encoding="utf-8")
    click.echo(f"Created {config_path}")


# ---------------------------------------------------------------------------
# Main entry point: the _ScanGroup that routes calls appropriately
# ---------------------------------------------------------------------------

main = _ScanGroup(
    name="mcpaudit",
    help="Scan Python MCP server code for security vulnerabilities.",
    commands={"scan": _scan, "init": _init},
    params=[
        click.Option(
            ["--version"],
            is_flag=True,
            is_eager=True,
            expose_value=False,
            callback=lambda ctx, _param, value: (
                click.echo(f"mcpaudit {_VERSION}") or ctx.exit()
            ) if value else None,
            help="Show the version and exit.",
        ),
    ],
)


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
