"""
TESSERA MCP Server

Provides TESSERA security scanning as an MCP (Model Context Protocol) server.

Usage:
    python -m tessera.infra.mcp.server

This starts an MCP server that exposes TESSERA's security scanning
capabilities to AI assistants.
"""

from typing import Any
from dataclasses import dataclass

from tessera.engine.scanner import Tesseract, OutputFormat


@dataclass
class ScanTool:
    """MCP tool for security scanning."""

    name: str = "tessera_scan"
    description: str = "Scan an AI agent topology for security vulnerabilities"
    input_schema: dict = None

    def __post_init__(self):
        self.input_schema = {
            "type": "object",
            "properties": {
                "topology_yaml": {
                    "type": "string",
                    "description": "YAML content of the agent topology to scan",
                },
                "format": {
                    "type": "string",
                    "enum": ["text", "json", "sarif", "html"],
                    "default": "json",
                    "description": "Output format",
                },
            },
            "required": ["topology_yaml"],
        }

    def execute(self, topology_yaml: str, format: str = "json") -> dict:
        """Execute the scan."""
        from tessera.core.topology.loader import Loader
        from io import StringIO

        # Load topology from YAML string
        loader = Loader()
        graph = loader.load_from_string(topology_yaml)

        # Scan
        scanner = Tesseract()
        format_enum = OutputFormat(format.lower())
        result = scanner.scan(graph, format_enum)

        return result


class TesseraMCPServer:
    """MCP server for TESSERA."""

    def __init__(self):
        self.tools = [ScanTool()]

    def get_tools(self) -> list[dict]:
        """Get list of available tools."""
        return [
            {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema}
            for tool in self.tools
        ]

    def execute_tool(self, tool_name: str, arguments: dict) -> Any:
        """Execute a tool."""
        for tool in self.tools:
            if tool.name == tool_name:
                return tool.execute(**arguments)
        raise ValueError(f"Unknown tool: {tool_name}")


def main():
    """Main entry point for MCP server."""
    import json

    server = TesseraMCPServer()

    # Simple JSON-RPC-like interface
    # In production, use proper MCP protocol
    print(json.dumps({"tools": server.get_tools()}, indent=2))


if __name__ == "__main__":
    main()
