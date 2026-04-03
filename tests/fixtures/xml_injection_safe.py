"""
Safe MCP tool handlers: use defusedxml or parse only static XML content.
This file should produce zero XML injection findings.
"""
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as safe_ET
from unittest.mock import MagicMock

mcp = MagicMock()

STATIC_CONFIG = "<config><version>1.0</version></config>"


@mcp.tool()
def parse_xml_defusedxml(xml_data: str) -> str:
    """Parse user-supplied XML with defusedxml — SAFE."""
    root = safe_ET.fromstring(xml_data)
    return root.tag


@mcp.tool()
def parse_static_xml(name: str) -> str:
    """Parse a hardcoded XML string — SAFE (no user input flows into parser)."""
    root = ET.fromstring(STATIC_CONFIG)
    version = root.find("version")
    return f"{version.text if version is not None else ''} {name}"


@mcp.tool()
def process_xml_name(schema_type: str) -> str:
    """Select a static schema via allowlist subscript — SAFE."""
    schemas = {
        "v1": "<schema><type>basic</type></schema>",
        "v2": "<schema><type>extended</type></schema>",
    }
    # Subscript on a non-tainted container is safe: taint doesn't flow from key to value.
    key = schema_type if schema_type in schemas else "v1"
    xml_content = schemas[key]
    root = ET.fromstring(xml_content)
    return root.find("type").text or ""
