"""
Data Pipeline for TESSERA RDT.
Converts YAML topologies to tensors for GNN/RDT training.
"""

import json
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from typing import Optional, Callable
from pathlib import Path
import random


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

NODE_TYPE_TO_IDX = {
    "llm": 0,
    "model": 1,
    "rag_corpus": 2,
    "tool": 3,
    "memory_store": 4,
    "database": 5,
    "api": 6,
    "filesystem": 7,
    "user": 8,
    "agent": 9,
    "external_service": 10,
    "cache": 11,
    "queue": 12,
    "logger": 13,
    "auth": 14,
}

TRUST_TO_IDX = {
    "public": 0,
    "external": 1,
    "user_controlled": 2,
    "partially_trusted": 3,
    "internal": 4,
    "privileged": 5,
}

DATA_FLOW_TO_IDX = {
    "retrieval": 0,
    "tool_call": 1,
    "read_write": 2,
    "api": 3,
    "inference": 4,
    "signal": 5,
}

VULN_CLASS_TO_IDX = {
    "benign": 0,
    "suspicious": 1,
    "high": 2,
    "critical": 3,
}

IDX_TO_VULN_CLASS = {v: k for k, v in VULN_CLASS_TO_IDX.items()}


# ----------------------------------------------------------------------
# Data Classes
# ----------------------------------------------------------------------


class GraphSample:
    """Single graph sample for training."""

    def __init__(
        self,
        node_types: torch.Tensor,  # (num_nodes,)
        node_trust: torch.Tensor,  # (num_nodes,)
        edge_src: torch.Tensor,  # (num_edges,)
        edge_dst: torch.Tensor,  # (num_edges,)
        edge_flows: torch.Tensor,  # (num_edges,)
        edge_trust: torch.Tensor,  # (num_edges,)
        vuln_label: int,  # scalar
        edge_labels: Optional[torch.Tensor] = None,  # (num_edges,) per-edge labels
    ):
        self.node_types = node_types
        self.node_trust = node_trust
        self.edge_src = edge_src
        self.edge_dst = edge_dst
        self.edge_flows = edge_flows
        self.edge_trust = edge_trust
        self.vuln_label = vuln_label
        self.edge_labels = edge_labels

    @property
    def num_nodes(self) -> int:
        return self.node_types.shape[0]

    @property
    def num_edges(self) -> int:
        return self.edge_src.shape[0]


# ----------------------------------------------------------------------
# YAML to Tensor Converter
# ----------------------------------------------------------------------


def topology_from_dict(data: dict) -> GraphSample:
    """
    Convert YAML-loaded topology to tensor representation.

    Args:
        dict with: nodes, edges, vuln_class, vulnerable_edges

    Returns:
        GraphSample
    """
    # Encode nodes
    node_ids = {}
    node_types_list = []
    node_trust_list = []

    for i, node_dict in enumerate(data.get("nodes", [])):
        node_id = node_dict["id"]
        node_ids[node_id] = i

        node_type = node_dict.get("type", "api")
        trust = node_dict.get("trust_boundary", "internal")

        node_types_list.append(NODE_TYPE_TO_IDX.get(node_type, 6))
        node_trust_list.append(TRUST_TO_IDX.get(trust, 4))

    # Encode edges
    edge_src_list = []
    edge_dst_list = []
    edge_flows_list = []
    edge_trust_list = []

    for edge_dict in data.get("edges", []):
        from_id = edge_dict.get("from") or edge_dict.get("from_node")
        to_id = edge_dict.get("to") or edge_dict.get("to_node")

        if from_id in node_ids and to_id in node_ids:
            edge_src_list.append(node_ids[from_id])
            edge_dst_list.append(node_ids[to_id])

            flow = edge_dict.get("data_flow", "api")
            trust = edge_dict.get("trust_boundary", "internal")

            edge_flows_list.append(DATA_FLOW_TO_IDX.get(flow, 3))
            edge_trust_list.append(TRUST_TO_IDX.get(trust, 4))

    # Labels
    vuln_class = data.get("vuln_class", "benign")
    vuln_label = VULN_CLASS_TO_IDX.get(vuln_class, 0)

    # Edge-level labels (for edge classification)
    vulnerable_edges_set = set(data.get("vulnerable_edges", []))
    edge_labels_list = []

    for edge_dict in data.get("edges", []):
        from_id = edge_dict.get("from") or edge_dict.get("from_node")
        to_id = edge_dict.get("to") or edge_dict.get("to_node")
        edge_id = f"{from_id}->{to_id}"

        if edge_id in vulnerable_edges_set:
            edge_labels_list.append(1)  # vulnerable
        else:
            edge_labels_list.append(0)  # benign

    # Convert to tensors
    node_types = torch.tensor(node_types_list, dtype=torch.long)
    node_trust = torch.tensor(node_trust_list, dtype=torch.long)
    edge_src = torch.tensor(edge_src_list, dtype=torch.long)
    edge_dst = torch.tensor(edge_dst_list, dtype=torch.long)
    edge_flows = torch.tensor(edge_flows_list, dtype=torch.long)
    edge_trust = torch.tensor(edge_trust_list, dtype=torch.long)
    edge_labels = torch.tensor(edge_labels_list, dtype=torch.long) if edge_labels_list else None

    return GraphSample(
        node_types=node_types,
        node_trust=node_trust,
        edge_src=edge_src,
        edge_dst=edge_dst,
        edge_flows=edge_flows,
        edge_trust=edge_trust,
        vuln_label=vuln_label,
        edge_labels=edge_labels,
    )


# ----------------------------------------------------------------------
# Dataset
# ----------------------------------------------------------------------


class AttackGraphDataset(Dataset):
    """Dataset for attack graph classification."""

    def __init__(
        self,
        jsonl_path: str,
        node_dim: int = 128,
        edge_dim: int = 128,
        augment: bool = False,
    ):
        self.jsonl_path = jsonl_path
        self.node_dim = node_dim
        self.edge_dim = edge_dim
        self.augment = augment

        self.samples: list[GraphSample] = []
        self._load()

    def _load(self):
        """Load samples from JSONL file."""
        with open(self.jsonl_path) as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    sample = topology_from_dict(data)
                    self.samples.append(sample)

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> GraphSample:
        sample = self.samples[idx]

        if self.augment:
            sample = self._augment(sample)

        return sample

    def _augment(self, sample: GraphSample) -> GraphSample:
        """Apply data augmentation."""
        # Random edge dropout (10% probability)
        if random.random() < 0.1 and sample.num_edges > 2:
            # Keep at least 2 edges
            keep_mask = torch.rand(sample.num_edges) > 0.1
            if keep_mask.sum() < 2:
                keep_mask = torch.ones(sample.num_edges, dtype=torch.bool)

            return GraphSample(
                node_types=sample.node_types,
                node_trust=sample.node_trust,
                edge_src=sample.edge_src[keep_mask],
                edge_dst=sample.edge_dst[keep_mask],
                edge_flows=sample.edge_flows[keep_mask],
                edge_trust=sample.edge_trust[keep_mask],
                vuln_label=sample.vuln_label,
                edge_labels=sample.edge_labels[keep_mask]
                if sample.edge_labels is not None
                else None,
            )

        return sample


# ----------------------------------------------------------------------
# Node Embedding (for model input)
# ----------------------------------------------------------------------


class NodeEmbedder(nn.Module):
    """Embeds node types and trust levels to feature vectors."""

    def __init__(
        self,
        vocab_size: int = 20,
        num_trust: int = 6,
        dim: int = 128,
    ):
        super().__init__()
        self.type_embed = nn.Embedding(vocab_size, dim)
        self.trust_embed = nn.Embedding(num_trust, dim)

    def forward(self, node_types: torch.Tensor, node_trust: torch.Tensor) -> torch.Tensor:
        """Embed node features."""
        return self.type_embed(node_types) + self.trust_embed(node_trust)


class EdgeEmbedder(nn.Module):
    """Embeds edge features to feature vectors."""

    def __init__(
        self,
        num_flows: int = 6,
        num_trust: int = 6,
        dim: int = 128,
    ):
        super().__init__()
        self.flow_embed = nn.Embedding(num_flows, dim)
        self.trust_embed = nn.Embedding(num_trust, dim)

    def forward(self, edge_flows: torch.Tensor, edge_trust: torch.Tensor) -> torch.Tensor:
        """Embed edge features."""
        return self.flow_embed(edge_flows) + self.trust_embed(edge_trust)


# ----------------------------------------------------------------------
# Collate Function
# ----------------------------------------------------------------------


def collate_graphs(batch: list[GraphSample]) -> dict:
    """
    Collate function for batching graphs of different sizes.

    Returns dict with:
    - node_types: list of tensors
    - node_features: list of tensors
    - edge_index: list of tensors
    - edge_features: list of tensors
    - vuln_labels: tensor
    """
    node_types = [s.node_types for s in batch]
    node_trust = [s.node_trust for s in batch]
    edge_src = [s.edge_src for s in batch]
    edge_dst = [s.edge_dst for s in batch]
    edge_flows = [s.edge_flows for s in batch]
    edge_trust = [s.edge_trust for s in batch]
    vuln_labels = torch.tensor([s.vuln_label for s in batch], dtype=torch.long)

    # Edge labels (optional)
    edge_labels = [s.edge_labels for s in batch if s.edge_labels is not None]
    if edge_labels and edge_labels[0] is not None:
        edge_labels = (
            torch.stack(edge_labels) if len(set(e.shape[0] for e in edge_labels)) == 1 else None
        )
    else:
        edge_labels = None

    return {
        "node_types": node_types,
        "node_trust": node_trust,
        "edge_src": edge_src,
        "edge_dst": edge_dst,
        "edge_flows": edge_flows,
        "edge_trust": edge_trust,
        "vuln_labels": vuln_labels,
        "edge_labels": edge_labels,
    }


# ----------------------------------------------------------------------
# DataLoader Factory
# ----------------------------------------------------------------------


def create_dataloaders(
    data_dir: str,
    batch_size: int = 32,
    node_dim: int = 128,
    edge_dim: int = 128,
    augment_train: bool = True,
) -> dict[str, DataLoader]:
    """
    Create train/val/test dataloaders.
    """
    train_dataset = AttackGraphDataset(
        f"{data_dir}/train.jsonl",
        node_dim=node_dim,
        edge_dim=edge_dim,
        augment=augment_train,
    )

    val_dataset = AttackGraphDataset(
        f"{data_dir}/val.jsonl",
        node_dim=node_dim,
        edge_dim=edge_dim,
        augment=False,
    )

    test_dataset = AttackGraphDataset(
        f"{data_dir}/test.jsonl",
        node_dim=node_dim,
        edge_dim=edge_dim,
        augment=False,
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=collate_graphs,
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=collate_graphs,
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=collate_graphs,
    )

    return {
        "train": train_loader,
        "val": val_loader,
        "test": test_loader,
    }


# ----------------------------------------------------------------------
# Test
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # Test with sample data
    print("Testing data pipeline...")

    # Create embedders
    node_embedder = NodeEmbedder()
    edge_embedder = EdgeEmbedder()

    # Test embedding
    node_types = torch.tensor([0, 3, 2, 1, 4])
    node_trust = torch.tensor([4, 4, 3, 2, 1])

    node_features = node_embedder(node_types, node_trust)
    print(f"Node features shape: {node_features.shape}")

    # Test edge
    edge_flows = torch.tensor([1, 0, 2, 1, 3])
    edge_trust = torch.tensor([4, 4, 3, 2, 1])

    edge_features = edge_embedder(edge_flows, edge_trust)
    print(f"Edge features shape: {edge_features.shape}")

    print("Data pipeline OK")
