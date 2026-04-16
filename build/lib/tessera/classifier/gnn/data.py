from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import numpy as np
from tessera.topology.models import NodeType


class EdgeType(str, Enum):
    PROMPT = "prompt"
    RESPONSE = "response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    RETRIEVAL = "retrieval"
    READ_WRITE = "read_write"


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    SANDBOXED = "sandboxed"
    TRUSTED = "trusted"
    PARTIALLY_TRUSTED = "partially_trusted"
    USER_CONTROLLED = "user_controlled"
    INTERNAL_TRUSTED = "internal_trusted"
    INTERNAL = "internal"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    trust: TrustLevel = TrustLevel.TRUSTED
    model: Optional[str] = None
    description: str = ""
    features: np.ndarray | None = None


@dataclass
class GraphEdge:
    from_node: str
    to_node: str
    edge_type: EdgeType
    trust: TrustLevel = TrustLevel.TRUSTED
    weight: float = 1.0


@dataclass
class TopologyGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    def get_adjacency(self) -> dict[str, list[str]]:
        adj = {nid: [] for nid in self.nodes}
        for edge in self.edges:
            if edge.from_node in adj:
                adj[edge.from_node].append(edge.to_node)
        return adj

    def get_edge_types_matrix(self) -> list[list[int]]:
        n = len(self.nodes)
        matrix = [[0] * n for _ in range(n)]
        node_ids = list(self.nodes.keys())
        for edge in self.edges:
            try:
                i = node_ids.index(edge.from_node)
                j = node_ids.index(edge.to_node)
                matrix[i][j] = EdgeType(edge.edge_type).value
            except (ValueError, IndexError):
                pass
        return matrix

    def to_feature_matrix(self) -> np.ndarray:
        node_ids = list(self.nodes.keys())
        n = len(node_ids)
        feature_dim = 16
        features = np.zeros((n, feature_dim))

        type_encoding = {
            NodeType.LLM: [1, 0, 0, 0, 0, 0, 0],
            NodeType.MODEL: [1, 0, 0, 0, 0, 0, 0],
            NodeType.RAG: [0, 1, 0, 0, 0, 0, 0],
            NodeType.RAG_CORPUS: [0, 1, 0, 0, 0, 0, 0],
            NodeType.TOOL: [0, 0, 1, 0, 0, 0, 0],
            NodeType.MEMORY: [0, 0, 0, 1, 0, 0, 0],
            NodeType.API: [0, 0, 0, 0, 1, 0, 0],
            NodeType.USER_INPUT: [0, 0, 0, 0, 0, 1, 0],
            NodeType.OUTPUT: [0, 0, 0, 0, 0, 0, 1],
        }

        trust_encoding = {
            TrustLevel.UNTRUSTED: [1, 0, 0],
            TrustLevel.USER_CONTROLLED: [1, 0, 0],
            TrustLevel.SANDBOXED: [0, 1, 0],
            TrustLevel.PARTIALLY_TRUSTED: [0, 1, 0],
            TrustLevel.TRUSTED: [0, 0, 1],
            TrustLevel.INTERNAL_TRUSTED: [0, 0, 1],
            TrustLevel.INTERNAL: [0, 0, 1],
        }

        for i, nid in enumerate(node_ids):
            node = self.nodes[nid]
            features[i, :7] = type_encoding.get(node.node_type, [0] * 7)
            features[i, 7:10] = trust_encoding.get(node.trust, [0] * 3)
            features[i, 10:] = np.random.rand(6) * 0.1

        return features

    def get_attack_paths(self) -> list[list[str]]:
        paths = []
        untrusted_nodes = [nid for nid, n in self.nodes.items() if n.trust == TrustLevel.UNTRUSTED]
        trusted_nodes = [nid for nid, n in self.nodes.items() if n.trust == TrustLevel.TRUSTED]

        for untrusted in untrusted_nodes:
            for trusted in trusted_nodes:
                if self._has_path(untrusted, trusted):
                    paths.append([untrusted, trusted])

        return paths

    def _has_path(self, start: str, end: str) -> bool:
        visited = set()
        queue = [start]
        while queue:
            current = queue.pop(0)
            if current == end:
                return True
            if current in visited:
                continue
            visited.add(current)
            adj = self.get_adjacency()
            queue.extend(adj.get(current, []))
        return False
