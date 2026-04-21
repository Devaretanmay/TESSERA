"""
GNN Baseline - Message Passing Graph Neural Network for 2-hop attack detection.
Simple baseline without torch-geometric for minimal dependencies.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class GraphData:
    """Simple graph data structure for GNN."""

    num_nodes: int
    edge_index: torch.Tensor  # (2, num_edges)
    node_features: torch.Tensor  # (num_nodes, feature_dim)
    edge_features: Optional[torch.Tensor] = None  # (num_edges, feature_dim)
    labels: Optional[torch.Tensor] = None  # (num_nodes,) or (num_edges,)
    node_types: Optional[torch.Tensor] = None
    trust_levels: Optional[torch.Tensor] = None


class MessagePassingLayer(nn.Module):
    """
    Simple message passing layer for graph neural networks.
    Implements: h_v^(l+1) = UPDATE(h_v^(l), AGG({m_uv : u in N(v)}))
    """

    def __init__(
        self,
        in_dim: int,
        out_dim: int,
        aggr: str = "mean",  # "mean", "sum", "max"
    ):
        super().__init__()
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.aggr = aggr

        # Message transformation
        self.msg_fn = nn.Sequential(
            nn.Linear(in_dim * 2, out_dim),
            nn.ReLU(),
            nn.Linear(out_dim, out_dim),
        )

        # Self-loop transformation
        self.self_fn = nn.Linear(in_dim, out_dim)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            x: (num_nodes, in_dim) - node features
            edge_index: (2, num_edges) - edge connectivity

        Returns:
            out: (num_nodes, out_dim) - updated node features
        """
        num_nodes = x.shape[0]
        src, dst = edge_index[0], edge_index[1]

        # Self features
        h_self = self.self_fn(x)

        # Message from neighbors
        h_src = x[src]  # (num_edges, in_dim)
        h_dst = x[dst]  # (num_edges, in_dim)

        # Concatenate source and destination for message
        msg = torch.cat([h_src, h_dst], dim=-1)  # (num_edges, in_dim * 2)
        msg = self.msg_fn(msg)  # (num_edges, out_dim)

        # Aggregate messages per destination node
        out = torch.zeros(num_nodes, self.out_dim, device=x.device)

        if self.aggr == "sum":
            # Sum aggregation
            out = out.scatter_add(0, dst.unsqueeze(-1).expand_as(msg), msg)
        elif self.aggr == "mean":
            # Mean aggregation
            out = out.scatter_add(0, dst.unsqueeze(-1).expand_as(msg), msg)
            # Count neighbors per node
            deg = torch.bincount(dst, minlength=num_nodes).float().clamp(min=1)
            out = out / deg.unsqueeze(-1)
        elif self.aggr == "max":
            # Max aggregation - use scatter
            out = out.scatter_reduce(0, dst.unsqueeze(-1).expand_as(msg), msg, reduce="amax")

        # Add self features
        out = out + h_self

        return out


class GraphAttentionLayer(nn.Module):
    """
    Graph Attention Network (GAT) style layer.
    Implements: h_v^(l+1) = sum(attention(u,v) * W * h_u) + self-attention
    """

    def __init__(
        self,
        in_dim: int,
        out_dim: int,
        heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.heads = heads
        self.head_dim = out_dim // heads

        assert out_dim % heads == 0, "out_dim must be divisible by heads"

        # Query, Key, Value projections
        self.W_q = nn.Linear(in_dim, out_dim)
        self.W_k = nn.Linear(in_dim, out_dim)
        self.W_v = nn.Linear(in_dim, out_dim)

        # Output projection
        self.W_o = nn.Linear(out_dim, out_dim)

        self.dropout = nn.Dropout(dropout)
        self.leaky_relu = nn.LeakyReLU(0.2)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            x: (num_nodes, in_dim)
            edge_index: (2, num_edges)

        Returns:
            out: (num_nodes, out_dim)
        """
        num_nodes = x.shape[0]
        src, dst = edge_index[0], edge_index[1]

        # Linear projections
        Q = self.W_q(x).view(num_nodes, self.heads, self.head_dim)
        K = self.W_k(x).view(num_nodes, self.heads, self.head_dim)
        V = self.W_v(x).view(num_nodes, self.heads, self.head_dim)

        # Compute attention scores
        # Q[src] @ K[dst] -> (num_edges, heads)
        attn_scores = (Q[src] * K[dst]).sum(dim=-1) / (self.head_dim**0.5)
        attn_scores = self.leaky_relu(attn_scores)

        # Masked softmax (no mask for now, add if needed)
        attn_weights = F.softmax(attn_scores, dim=0)
        attn_weights = self.dropout(attn_weights)

        # Aggregate values
        out = torch.zeros(num_nodes, self.heads, self.head_dim, device=x.device)
        out = out.scatter_add(
            0,
            dst.unsqueeze(-1).unsqueeze(-1).expand_as(V[src]),
            attn_weights.unsqueeze(-1) * V[src],
        )

        # Concatenate heads and project
        out = out.contiguous().view(num_nodes, -1)
        out = self.W_o(out)

        return out


class GNNBlock(nn.Module):
    """GNN block with message passing + normalization + activation."""

    def __init__(
        self,
        dim: int,
        heads: int = 4,
        dropout: float = 0.1,
        use_gat: bool = True,
    ):
        super().__init__()

        if use_gat:
            self.conv = GraphAttentionLayer(dim, dim, heads, dropout)
        else:
            self.conv = MessagePassingLayer(dim, dim, "mean")

        self.norm = nn.LayerNorm(dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = self.conv(x, edge_index)
        h = self.dropout(h)
        h = self.norm(x + h)  # Residual connection
        return h


class GNNBaseline(nn.Module):
    """
    Baseline GNN for 2-hop attack chain detection.

    Architecture:
    - Input encoding
    - 2-3 GNN layers for 2-hop neighborhood aggregation
    - Classification head

    This baseline detects vulnerabilities by:
    1. Encoding node/edge features
    2. Propagating information through graph (2 hops)
    3. Classifying nodes/edges as vulnerable or not
    """

    def __init__(
        self,
        input_dim: int = 256,
        hidden_dim: int = 128,
        num_layers: int = 3,
        num_classes: int = 4,  # benign, suspicious, high, critical
        dropout: float = 0.1,
        use_gat: bool = True,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_classes = num_classes

        # Input projection
        self.input_proj = nn.Linear(input_dim, hidden_dim)

        # GNN layers
        self.gnn_layers = nn.ModuleList(
            [
                GNNBlock(hidden_dim, heads=4, dropout=dropout, use_gat=use_gat)
                for _ in range(num_layers)
            ]
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes),
        )

    def forward(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            node_features: (num_nodes, input_dim)
            edge_index: (2, num_edges)

        Returns:
            logits: (num_nodes, num_classes)
        """
        # Input projection
        h = self.input_proj(node_features)

        # GNN layers (2-hop neighborhood aggregation)
        for layer in self.gnn_layers:
            h = layer(h, edge_index)

        # Classification
        logits = self.classifier(h)

        return logits

    def predict(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Get predictions and probabilities.

        Returns:
            predictions: (num_nodes,) - class indices
            probs: (num_nodes, num_classes) - class probabilities
        """
        with torch.no_grad():
            logits = self.forward(node_features, edge_index)
            probs = F.softmax(logits, dim=-1)
            predictions = probs.argmax(dim=-1)

        return predictions, probs


class EdgeClassifier(nn.Module):
    """
    Edge-level classifier for attack chain detection.
    Classifies edges rather than nodes.
    """

    def __init__(
        self,
        node_dim: int = 256,
        edge_dim: int = 128,
        hidden_dim: int = 128,
        num_layers: int = 2,
        num_classes: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()

        # Node encoding
        self.node_encoder = nn.Sequential(
            nn.Linear(node_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

        # Edge encoding
        self.edge_encoder = nn.Sequential(
            nn.Linear(edge_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

        # GNN for edge features
        self.gnn = nn.ModuleList(
            [MessagePassingLayer(hidden_dim, hidden_dim, "mean") for _ in range(num_layers)]
        )

        # Edge classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 3, hidden_dim),  # src + dst + edge
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(
        self,
        node_features: torch.Tensor,
        edge_features: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            node_features: (num_nodes, node_dim)
            edge_features: (num_edges, edge_dim)
            edge_index: (2, num_edges)

        Returns:
            logits: (num_edges, num_classes)
        """
        # Encode nodes
        h_nodes = self.node_encoder(node_features)

        # GNN layers
        for layer in self.gnn:
            h_nodes = layer(h_nodes, edge_index)

        # Get source and destination node features
        src, dst = edge_index[0], edge_index[1]
        h_src = h_nodes[src]
        h_dst = h_nodes[dst]

        # Encode edges
        h_edge = self.edge_encoder(edge_features)

        # Concatenate src + dst + edge features
        h_combined = torch.cat([h_src, h_dst, h_edge], dim=-1)

        # Classify
        logits = self.classifier(h_combined)

        return logits

    def predict(
        self,
        node_features: torch.Tensor,
        edge_features: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get edge predictions."""
        with torch.no_grad():
            logits = self.forward(node_features, edge_features, edge_index)
            probs = F.softmax(logits, dim=-1)
            predictions = probs.argmax(dim=-1)

        return predictions, probs


def count_parameters(model: nn.Module) -> int:
    """Count trainable parameters."""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


# Test code
if __name__ == "__main__":
    # Test GNN baseline
    gnn = GNNBaseline(input_dim=256, hidden_dim=128, num_layers=3)
    print(f"GNN Baseline params: {count_parameters(gnn):,}")

    # Dummy input
    num_nodes = 10
    num_edges = 15
    x = torch.randn(num_nodes, 256)
    edge_index = torch.randint(0, num_nodes, (2, num_edges))

    # Forward pass
    logits = gnn(x, edge_index)
    print(f"Output shape: {logits.shape}")  # (10, 4)

    # Test edge classifier
    edge_clf = EdgeClassifier(node_dim=256, edge_dim=128)
    print(f"Edge Classifier params: {count_parameters(edge_clf):,}")

    edge_features = torch.randn(num_edges, 128)
    edge_logits = edge_clf(x, edge_features, edge_index)
    print(f"Edge output shape: {edge_logits.shape}")  # (15, 4)
