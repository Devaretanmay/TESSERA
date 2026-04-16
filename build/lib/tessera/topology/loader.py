import yaml
from pathlib import Path
from tessera.topology.models import (
    TopologyGraph,
    TopologyNode,
    TopologyEdge,
    NodeType,
    TrustBoundary,
    FlowType,
    TrustLevel,
)


class TopologyLoader:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.errors = []

    def load(self) -> TopologyGraph:
        with open(self.path) as f:
            data = yaml.safe_load(f)

        graph = TopologyGraph(
            system=data.get("name") or data.get("system", "unknown"),
            version=data.get("version", "1.0"),
        )

        for node_data in data.get("nodes", []):
            node = TopologyNode(
                id=node_data["id"],
                type=NodeType(node_data["type"]),
                provider=node_data.get("provider"),
                model=node_data.get("model"),
                trust_boundary=TrustBoundary(node_data.get("trust_boundary", "partially_trusted")),
                config=node_data.get("config", {}),
                capabilities=node_data.get("capabilities", []),
                backend=node_data.get("backend"),
                index=node_data.get("index"),
                schema_url=node_data.get("schema_url"),
                ttl=node_data.get("ttl"),
            )
            graph.add_node(node)

        for edge_data in data.get("edges", []):
            edge = TopologyEdge(
                from_node=edge_data["from"],
                to_node=edge_data["to"],
                flow=FlowType(edge_data["flow"]),
                trust_level=TrustLevel(edge_data.get("trust_level", "untrusted")),
            )
            graph.add_edge(edge)

        return graph

    def validate(self) -> tuple[bool, list[str]]:
        graph = self.load()
        errors = []

        if not graph.nodes:
            errors.append("No nodes defined")

        untrusted_nodes = [
            n for n in graph.nodes.values() if n.trust_boundary == TrustBoundary.USER_CONTROLLED
        ]
        if not untrusted_nodes:
            errors.append("No user-controlled nodes defined")

        untrusted_edges = [e for e in graph.edges if e.trust_level == TrustLevel.UNTRUSTED]
        if not untrusted_edges:
            errors.append("No untrusted edges - attack surface may be empty")

        return len(errors) == 0, errors
