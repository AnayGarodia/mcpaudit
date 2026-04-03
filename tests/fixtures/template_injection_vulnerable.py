"""
Vulnerable MCP tool handler: passes raw user input into template constructors.
This file is intentionally insecure — used as a detection fixture for mcpaudit.

Expected findings: 3
"""
import jinja2
from jinja2 import Template
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def render_template_direct(template_str: str) -> str:
    """Render a user-supplied Jinja2 template — SSTI risk."""
    tmpl = jinja2.Template(template_str)
    return tmpl.render()


@mcp.tool()
def render_from_string(user_template: str) -> str:
    """Render via Environment.from_string with user input — SSTI risk."""
    env = jinja2.Environment()
    tmpl = env.from_string(user_template)
    return tmpl.render()


@mcp.tool()
def render_imported_template(user_template: str) -> str:
    """Render via directly imported Template class — SSTI risk."""
    tmpl = Template(user_template)
    return tmpl.render()
