"""
RDT Graph Encoder - Node and Edge encoding for TESSERA topology.
Converts YAML topology to embeddings for RDT model.
"""

import torch
import torch.nn as nn
from typing import Optional
from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary, DataFlow


class NodeEncoder(nn.Module):
    """
    Encodes node types, trust boundaries, and attributes into vectors.

    Embeddings:
    - Node type: vocab_size → dim
    - Trust boundary: 6 levels → dim
    - Provider: optional → dim

    Total output: 3 * dim (type + trust + provider)
    """

    # Node type vocabulary
    NODE_TYPES = [
        "llm",
        "model",
        "rag_corpus",
        "tool",
        "memory_store",
        "database",
        "api",
        "filesystem",
        "user",
        "agent",
        "external_service",
        "cache",
        "queue",
        "logger",
        "auth",
    ]

    def __init__(
        self,
        dim: int = 128,
        vocab_size: int = 20,
        num_trust_levels: int = 6,
        provider_dim: Optional[int] = None,
    ):
        super().__init__()
        self.dim = dim
        self.vocab_size = vocab_size
        self.num_trust_levels = num_trust_levels
        self.provider_dim = provider_dim or dim // 2

        # Node type embedding
        self.type_embed = nn.Embedding(vocab_size, dim)

        # Trust boundary embedding (6 levels from TrustBoundary enum)
        self.trust_embed = nn.Embedding(num_trust_levels, dim)

        # Provider embedding (optional)
        self.provider_embed = nn.Embedding(16, self.provider_dim)  # 16 common providers

        # Node attributes projection (for metadata)
        self.attr_proj = nn.Linear(32, dim)  # 32-dim attr vector

        self._build_type_to_idx()

    def _build_type_to_idx(self):
        """Build node type to index mapping."""
        self.type_to_idx = {t: i for i, t in enumerate(self.NODE_TYPES)}
        self.trust_to_idx = {t.value: i for i, t in enumerate(TrustBoundary)}

    def forward(
        self,
        node_types: torch.Tensor,
        trust_levels: torch.Tensor,
        providers: Optional[torch.Tensor] = None,
        node_attrs: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Args:
            node_types: (batch_size, num_nodes) - node type indices
            trust_levels: (batch_size, num_nodes) - trust boundary indices
            providers: (batch_size, num_nodes) - provider indices (optional)
            node_attrs: (batch_size, num_nodes, 32) - attribute vectors (optional)

        Returns:
            embeddings: (batch_size, num_nodes, 3 * dim)
        """
        # Type embedding
        type_emb = self.type_embed(node_types)  # (B, N, dim)

        # Trust embedding
        trust_emb = self.trust_embed(trust_levels)  # (B, N, dim)

        # Provider embedding (if provided)
        if providers is not None:
            provider_emb = self.provider_embed(providers)  # (B, N, provider_dim)
            # Pad to match dim
            provider_emb = torch.nn.functional.pad(provider_emb, (0, self.dim - self.provider_dim))
        else:
            provider_emb = torch.zeros_like(type_emb)

        # Attributes projection (if provided)
        if node_attrs is not None:
            attr_emb = self.attr_proj(node_attrs)  # (B, N, dim)
        else:
            attr_emb = torch.zeros_like(type_emb)

        # Concatenate all embeddings
        embeddings = torch.cat([type_emb, trust_emb, provider_emb], dim=-1)

        return embeddings

    def encode_node(self, node: Node) -> torch.Tensor:
        """Encode a single node for inference."""
        type_idx = self.type_to_idx.get(node.type, 0)
        trust_idx = self.trust_to_idx.get(node.trust_boundary.value, 0)

        type_tensor = torch.tensor([type_idx], dtype=torch.long)
        trust_tensor = torch.tensor([trust_idx], dtype=torch.long)

        with torch.no_grad():
            return self.forward(type_tensor.unsqueeze(0), trust_tensor.unsqueeze(0)).squeeze(0)


class EdgeEncoder(nn.Module):
    """
    Encodes edge types, trust boundaries, and weights.

    Embeddings:
    - Data flow type: 6 types → dim
    - Trust boundary: 6 levels → dim

    Total output: 2 * dim
    """

    DATA_FLOW_TYPES = ["retrieval", "tool_call", "read_write", "api", "inference", "signal"]

    def __init__(self, dim: int = 128, num_trust_levels: int = 6):
        super().__init__()
        self.dim = dim
        self.num_trust_levels = num_trust_levels

        # Data flow type embedding
        self.flow_embed = nn.Embedding(len(self.DATA_FLOW_TYPES), dim)

        # Trust boundary embedding
        self.trust_embed = nn.Embedding(num_trust_levels, dim)

        # Edge weight (learned or computed)
        self.weight = nn.Parameter(torch.ones(1) * 0.5)

        self._build_mapping()

    def _build_mapping(self):
        """Build mappings for encoding."""
        self.flow_to_idx = {f: i for i, f in enumerate(self.DATA_FLOW_TYPES)}
        self.trust_to_idx = {t.value: i for i, t in enumerate(TrustBoundary)}

    def forward(
        self,
        data_flows: torch.Tensor,
        trust_levels: torch.Tensor,
        edge_weights: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Args:
            data_flows: (batch_size, num_edges) - data flow type indices
            trust_levels: (batch_size, num_edges) - trust boundary indices
            edge_weights: (batch_size, num_edges) - edge weights (optional)

        Returns:
            embeddings: (batch_size, num_edges, 2 * dim)
        """
        # Flow embedding
        flow_emb = self.flow_embed(data_flows)  # (B, E, dim)

        # Trust embedding
        trust_emb = self.trust_embed(trust_levels)  # (B, E, dim)

        embeddings = torch.cat([flow_emb, trust_emb], dim=-1)

        return embeddings

    def encode_edge(self, edge: Edge) -> torch.Tensor:
        """Encode a single edge for inference."""
        flow_idx = self.flow_to_idx.get(edge.data_flow.value, 0)
        trust_idx = self.trust_to_idx.get(edge.trust_boundary.value, 0)

        flow_tensor = torch.tensor([flow_idx], dtype=torch.long)
        trust_tensor = torch.tensor([trust_idx], dtype=torch.long)

        with torch.no_grad():
            return self.forward(flow_tensor.unsqueeze(0), trust_tensor.unsqueeze(0)).squeeze(0)


class TopologyEncoder(nn.Module):
    """
    Complete topology encoder combining node and edge encoders.
    Converts TESSERA Graph to embeddings for RDT model.
    """

    def __init__(
        self,
        node_dim: int = 128,
        edge_dim: int = 128,
        hidden_dim: int = 256,
    ):
        super().__init__()
        self.node_encoder = NodeEncoder(dim=node_dim)
        self.edge_encoder = EdgeEncoder(dim=edge_dim)

        # Project to hidden dimension
        self.node_proj = nn.Linear(3 * node_dim, hidden_dim)
        self.edge_proj = nn.Linear(2 * edge_dim, hidden_dim)

    def forward(self, graph: Graph) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Convert TESSERA Graph to node and edge embeddings.

        Args:
            graph: TESSERA Graph object

        Returns:
            node_embeddings: (num_nodes, hidden_dim)
            edge_embeddings: (num_edges, hidden_dim)
        """
        # Encode nodes
        node_list = list(graph.nodes.values())
        node_types = []
        trust_levels = []

        for node in node_list:
            type_idx = self.node_encoder.type_to_idx.get(node.type, 0)
            trust_idx = self.node_encoder.trust_to_idx.get(node.trust_boundary.value, 0)
            node_types.append(type_idx)
            trust_levels.append(trust_idx)

        node_types_tensor = torch.tensor(node_types, dtype=torch.long).unsqueeze(0)
        trust_levels_tensor = torch.tensor(trust_levels, dtype=torch.long).unsqueeze(0)

        node_emb = self.node_encoder(node_types_tensor, trust_levels_tensor)
        node_emb = self.node_proj(node_emb).squeeze(0)  # (num_nodes, hidden_dim)

        # Encode edges
        edge_list = graph.edges
        data_flows = []
        trust_lvls = []

        for edge in edge_list:
            flow_idx = self.edge_encoder.flow_to_idx.get(edge.data_flow.value, 0)
            trust_idx = self.edge_encoder.trust_to_idx.get(edge.trust_boundary.value, 0)
            data_flows.append(flow_idx)
            trust_lvls.append(trust_idx)

        data_flows_tensor = torch.tensor(data_flows, dtype=torch.long).unsqueeze(0)
        trust_lvls_tensor = torch.tensor(trust_lvls, dtype=torch.long).unsqueeze(0)

        edge_emb = self.edge_encoder(data_flows_tensor, trust_lvls_tensor)
        edge_emb = self.edge_proj(edge_emb).squeeze(0)  # (num_edges, hidden_dim)

        return node_emb, edge_emb
