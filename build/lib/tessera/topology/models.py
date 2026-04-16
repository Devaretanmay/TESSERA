from pydantic import BaseModel, Field
from typing import Literal
from enum import Enum


class NodeType(str, Enum):
    MODEL = "model"
    LLM = "llm"
    RAG_CORPUS = "rag_corpus"
    RAG = "rag"
    TOOL = "tool"
    MEMORY = "memory"
    API = "api"
    USER_INPUT = "user_input"
    OUTPUT = "output"
    CODE_INTERPRETER = "code_interpreter"


class TrustBoundary(str, Enum):
    TRUSTED = "trusted"
    PARTIALLY_TRUSTED = "partially_trusted"
    USER_CONTROLLED = "user_controlled"
    INTERNAL_TRUSTED = "internal_trusted"
    UNTRUSTED = "untrusted"

    @classmethod
    def from_string(cls, value: str) -> "TrustBoundary":
        """Accept both TrustBoundary and TrustLevel values."""
        for member in cls:
            if member.value == value:
                return member
        return cls.TRUSTED


class FlowType(str, Enum):
    RETRIEVAL = "retrieval"
    TOOL_CALL = "tool_call"
    READ_WRITE = "read_write"
    API = "api"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    INTERNAL = "internal"
    # Aliases for TrustBoundary values
    PARTIALLY_TRUSTED = "partially_trusted"
    USER_CONTROLLED = "user_controlled"
    INTERNAL_TRUSTED = "internal_trusted"

    @classmethod
    def from_string(cls, value: str) -> "TrustLevel":
        """Accept both TrustLevel and TrustBoundary values."""
        # Direct match
        for member in cls:
            if member.value == value:
                return member
        # Try mapping aliases
        aliases = {
            "partially_trusted": cls.PARTIALLY_TRUSTED,
            "user_controlled": cls.USER_CONTROLLED,
            "internal_trusted": cls.INTERNAL_TRUSTED,
        }
        if value in aliases:
            return aliases[value]
        raise ValueError(f"Invalid trust value: {value}. Use: {[m.value for m in cls]}")


class TopologyNode(BaseModel):
    id: str = Field(..., description="Unique node identifier")
    type: NodeType = Field(..., description="Node type")
    provider: str | None = Field(None, description="Provider (e.g., openai, anthropic)")
    model: str | None = Field(None, description="Model name")
    trust_boundary: TrustBoundary = Field(..., description="Trust boundary classification")
    config: dict = Field(default_factory=dict, description="Node-specific config")
    capabilities: list[str] = Field(default_factory=list, description="Tool capabilities")
    backend: str | None = Field(None, description="Backend (e.g., pinecone, redis)")
    index: str | None = Field(None, description="Index name")
    schema_url: str | None = Field(None, description="Tool schema URL")
    ttl: int | None = Field(None, description="TTL in seconds")


class TopologyEdge(BaseModel):
    from_node: str = Field(..., description="Source node ID")
    to_node: str = Field(..., description="Target node ID")
    flow: FlowType = Field(..., description="Flow type")
    trust_level: TrustLevel = Field(..., description="Trust level")


class TopologyGraph(BaseModel):
    system: str = Field(..., description="System name")
    version: str = Field(default="1.0", description="System version")
    nodes: dict[str, TopologyNode] = Field(
        default_factory=dict, description="Node ID -> Node mapping"
    )
    edges: list[TopologyEdge] = Field(default_factory=list, description="Graph edges")

    def add_node(self, node: TopologyNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: TopologyEdge) -> None:
        if edge.from_node not in self.nodes:
            raise ValueError(f"Node {edge.from_node} not found")
        if edge.to_node not in self.nodes:
            raise ValueError(f"Node {edge.to_node} not found")
        self.edges.append(edge)

    def get_edges_from(self, node_id: str) -> list[TopologyEdge]:
        return [e for e in self.edges if e.from_node == node_id]

    def get_edges_to(self, node_id: str) -> list[TopologyEdge]:
        return [e for e in self.edges if e.to_node == node_id]

    def paths_between(self, start: str, end: str) -> list[list[str]]:
        if start not in self.nodes or end not in self.nodes:
            return []

        paths = []
        visited = set()

        def dfs(current: str, path: list[str]):
            if current == end:
                paths.append(path.copy())
                return
            if current in visited:
                return

            visited.add(current)
            for edge in self.get_edges_from(current):
                path.append(edge.to_node)
                dfs(edge.to_node, path)
                path.pop()
            visited.remove(current)

        dfs(start, [start])
        return paths

    def attack_surface(self) -> list[dict]:
        surface = []
        for edge in self.edges:
            if edge.trust_level == TrustLevel.UNTRUSTED:
                from_node = self.nodes[edge.from_node]
                to_node = self.nodes[edge.to_node]
                surface.append(
                    {
                        "edge": f"{edge.from_node}->{edge.to_node}",
                        "flow": edge.flow,
                        "untrusted_boundary": from_node.trust_boundary.value,
                    }
                )
        return surface
