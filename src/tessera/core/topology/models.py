"""
Core topology models - single source of truth for graph representation.

STRICT SCHEMA:
- All graph components use these models only
- No alternate formats, no implicit tuples
- Failure if data is missing rather than fallback
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class TrustBoundary(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVILEGED = "privileged"
    EXTERNAL = "external"
    USER_CONTROLLED = "user_controlled"
    PARTIALLY_TRUSTED = "partially_trusted"

    @classmethod
    def _missing_(cls, value: str):
        # Map unknown values to closest equivalent
        mapping = {
            "internal_trusted": cls.INTERNAL,
            "partially_trusted": cls.PARTIALLY_TRUSTED,
            "user_controlled": cls.USER_CONTROLLED,
        }
        return mapping.get(value.lower(), cls.INTERNAL)


class DataFlow(str, Enum):
    RETRIEVAL = "retrieval"
    TOOL_CALL = "tool_call"
    READ_WRITE = "read_write"
    API = "api"
    INFERENCE = "inference"
    SIGNAL = "signal"

    @classmethod
    def _missing_(cls, value: str):
        return cls.API  # Default for unknown


@dataclass(frozen=True)
class Edge:
    """Single-edge schema - no alternatives allowed."""

    from_node: str
    to_node: str
    trust_boundary: TrustBoundary
    data_flow: DataFlow

    def __post_init__(self):
        if isinstance(self.trust_boundary, str):
            object.__setattr__(self, "trust_boundary", TrustBoundary(self.trust_boundary))
        if isinstance(self.data_flow, str):
            object.__setattr__(self, "data_flow", DataFlow(self.data_flow))


@dataclass(frozen=True)
class Node:
    """Single-node schema."""

    id: str
    type: str
    provider: str | None = None
    trust_boundary: TrustBoundary = TrustBoundary.INTERNAL
    metadata: dict = field(default_factory=dict)


@dataclass
class Graph:
    """Immutable graph container."""

    system: str
    version: str = "1.0"
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def get_edges_from(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.from_node == node_id]

    def get_edges_to(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.to_node == node_id]

    def trust_crossing_edges(self) -> list[tuple[Edge, str, str]]:
        """Edges that cross trust boundaries."""
        crossings = []
        for edge in self.edges:
            from_nb = self.nodes.get(edge.from_node)
            to_nb = self.nodes.get(edge.to_node)
            if from_nb and to_nb and from_nb.trust_boundary != to_nb.trust_boundary:
                crossings.append((edge, from_nb.trust_boundary.value, to_nb.trust_boundary.value))
        return crossings

    def attack_surface(self) -> list[Edge]:
        """Edges with untrusted boundaries."""
        return [e for e in self.edges if e.trust_boundary == TrustBoundary.EXTERNAL]
