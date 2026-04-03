"""
Safe MCP tool handler: uses static templates with parameterized rendering.
This file should produce zero template injection findings.
"""
import jinja2
from jinja2 import Environment, FileSystemLoader
from unittest.mock import MagicMock

mcp = MagicMock()

# Static Jinja2 environment loading templates from files.
_env = Environment(loader=FileSystemLoader("templates/"))


@mcp.tool()
def render_with_context(username: str, count: int) -> str:
    """Render a static template with user data as context — SAFE."""
    tmpl = _env.get_template("report.html")
    return tmpl.render(username=username, count=count)


@mcp.tool()
def render_static_template(name: str) -> str:
    """Create template from a hard-coded string and inject user data as context — SAFE."""
    tmpl = jinja2.Template("Hello, {{ name }}!")
    return tmpl.render(name=name)


@mcp.tool()
def load_named_template(report_type: str) -> str:
    """Load template by a validated name — SAFE (literal string only)."""
    # report_type is used to pick, but we only pass a static string to Template.
    template_content = "Report: {{ data }}"
    tmpl = jinja2.Template(template_content)
    return tmpl.render(data=report_type)
