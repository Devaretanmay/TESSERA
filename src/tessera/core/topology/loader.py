"""
Topology loader - parses YAML into Graph.
"""

from pathlib import Path

import yaml

from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary, DataFlow


class ValidationError(Exception):
    pass


class Loader:
    def load(self, path: str | Path) -> Graph:
        source = Path(path)
        if not source.exists():
            raise ValidationError(f"File not found: {source}")
        data = self._parse_yaml(source.read_text(), source.name)
        return self._build_graph(data, source.name)

    def load_from_string(self, yaml_content: str) -> Graph:
        """Load topology from a YAML string.

        Args:
            yaml_content: YAML string content

        Returns:
            Graph object
        """
        data = self._parse_yaml(yaml_content, "<string>")
        return self._build_graph(data, "<string>")

    def _parse_yaml(self, content: str, source: str) -> dict:
        """Parse YAML and ensure mapping root."""
        data = yaml.safe_load(content) or {}
        if not isinstance(data, dict):
            raise ValidationError(f"{source}: invalid YAML root, expected mapping")
        return data

    def _build_graph(self, raw_data: dict, source: str) -> Graph:
        data = self._normalize_schema(raw_data)
        system = data.get("system") or data.get("system_name") or "unknown"

        if "nodes" not in data or "edges" not in data:
            raise ValidationError(f"{source}: missing nodes or edges")

        graph = Graph(system=system, version=data.get("version", "1.0"))

        nodes_data = data.get("nodes", [])
        if isinstance(nodes_data, dict):
            nodes_data = list(nodes_data.values())
        if not isinstance(nodes_data, list):
            raise ValidationError(f"{source}: nodes must be a list or mapping")

        for node_data in nodes_data:
            if not isinstance(node_data, dict):
                raise ValidationError(f"{source}: invalid node entry")
            node = Node(
                id=node_data["id"],
                type=node_data["type"],
                provider=node_data.get("provider"),
                trust_boundary=TrustBoundary(node_data.get("trust_boundary", "internal")),
                metadata=node_data.get("config", {}),
            )
            graph.add_node(node)

        edges_data = data.get("edges", [])
        if not isinstance(edges_data, list):
            raise ValidationError(f"{source}: edges must be a list")
        for edge_data in edges_data:
            if not isinstance(edge_data, dict):
                raise ValidationError(f"{source}: invalid edge entry")
            edge = Edge(
                from_node=edge_data.get("from") or edge_data.get("from_node", ""),
                to_node=edge_data.get("to") or edge_data.get("to_node", ""),
                trust_boundary=TrustBoundary(edge_data.get("trust_boundary", "internal")),
                data_flow=DataFlow(edge_data.get("flow", edge_data.get("data_flow", "api"))),
            )
            graph.add_edge(edge)

        return graph

    @staticmethod
    def _normalize_schema(data: dict) -> dict:
        """Accept top-level schema and nested `tessera` schema."""
        tessera_meta = data.get("tessera")
        if isinstance(tessera_meta, dict) and "system" in tessera_meta:
            return tessera_meta
        return data
