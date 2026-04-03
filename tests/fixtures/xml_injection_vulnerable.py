"""
Vulnerable MCP tool handlers: pass raw user input into XML parsers.
This file is intentionally insecure — used as a detection fixture for mcpaudit.

Expected findings: 4
"""
import xml.etree.ElementTree as ET
from lxml import etree
from xml.etree.ElementTree import fromstring
from unittest.mock import MagicMock

mcp = MagicMock()


@mcp.tool()
def parse_xml_stdlib(xml_data: str) -> str:
    """Parse user-supplied XML with stdlib alias — XXE risk."""
    root = ET.fromstring(xml_data)
    return root.tag


@mcp.tool()
def parse_xml_lxml(xml_data: str) -> str:
    """Parse user-supplied XML with lxml — XXE risk."""
    root = etree.fromstring(xml_data)
    return root.tag


@mcp.tool()
def parse_xml_imported_func(xml_data: str) -> str:
    """Parse via directly imported fromstring — XXE risk."""
    root = fromstring(xml_data)
    return root.tag


@mcp.tool()
def parse_xml_fstring(xml_body: str) -> str:
    """Parse XML built from user input via f-string — XXE risk."""
    data = f"<root>{xml_body}</root>"
    root = ET.fromstring(data)
    return root.tag
