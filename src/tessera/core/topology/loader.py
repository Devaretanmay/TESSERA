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
        path = Path(path)
        if not path.exists():
            raise ValidationError(f"File not found: {path}")

        data = yaml.safe_load(path.read_text())

        tessera_meta = data.get("tessera", {})
        if "system" in tessera_meta:
            data = tessera_meta

        system = data.get("system") or data.get("system_name") or "unknown"

        if "nodes" not in data or "edges" not in data:
            raise ValidationError(f"{path.name}: missing nodes or edges")

        graph = Graph(system=system, version=data.get("version", "1.0"))

        nodes_data = data.get("nodes", [])
        if isinstance(nodes_data, dict):
            nodes_data = list(nodes_data.values())

        for node_data in nodes_data:
            node = Node(
                id=node_data["id"],
                type=node_data["type"],
                provider=node_data.get("provider"),
                trust_boundary=TrustBoundary(node_data.get("trust_boundary", "internal")),
                metadata=node_data.get("config", {}),
            )
            graph.add_node(node)

        edges_data = data.get("edges", [])
        for edge_data in edges_data:
            edge = Edge(
                from_node=edge_data.get("from") or edge_data.get("from_node", ""),
                to_node=edge_data.get("to") or edge_data.get("to_node", ""),
                trust_boundary=TrustBoundary(edge_data.get("trust_boundary", "internal")),
                data_flow=DataFlow(edge_data.get("flow", edge_data.get("data_flow", "api"))),
            )
            graph.add_edge(edge)

        return graph
