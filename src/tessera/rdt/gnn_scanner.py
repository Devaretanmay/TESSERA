#!/usr/bin/env python3
"""
TESSERA GNN Scanner - Production-ready vulnerability detector
Uses the trained 82.9% F1 model
"""

import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from pathlib import Path
from typing import Optional, List, Dict, Any

NODE_TYPE_MAP = {
    "user": 0,
    "llm": 1,
    "api": 2,
    "tool": 3,
    "database": 4,
    "memory_store": 5,
    "rag_corpus": 6,
    "external_service": 7,
}
TRUST_MAP = {
    "external": 0,
    "public": 1,
    "user_controlled": 2,
    "partially_trusted": 3,
    "internal": 4,
    "privileged": 5,
}
FLOW_MAP = {
    "signal": 0,
    "api": 1,
    "tool_call": 2,
    "retrieval": 3,
    "inference": 4,
    "read_write": 5,
}


class Detector(nn.Module):
    def __init__(self, dim=128):
        super().__init__()
        self.ne = nn.Embedding(20, dim)
        self.te = nn.Embedding(6, dim)
        self.ef = nn.Embedding(6, dim)
        self.gru = nn.GRUCell(dim, dim)
        self.norm = nn.LayerNorm(dim)
        self.fc = nn.Sequential(
            nn.Linear(dim * 2, dim),
            nn.LayerNorm(dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(dim, 1),
        )

    def forward(self, nt, tr, es, ed, ef):
        # Handle batch dimension
        if nt.dim() > 1:
            nt = nt.squeeze(0)
        if tr.dim() > 1:
            tr = tr.squeeze(0)
        if es.dim() > 1:
            es = es.squeeze(0)
        if ed.dim() > 1:
            ed = ed.squeeze(0)
        if ef.dim() > 1:
            ef = ef.squeeze(0)

        h = self.ne(nt) + self.te(tr)
        edge_feat = self.ef(ef)

        for _ in range(5):
            agg = torch.zeros_like(h)
            cnt = torch.zeros(32, device=h.device)
            for j in range(ed.size(0)):
                d = ed[j].item()
                s = es[j].item()
                if d < 32 and s < 32:
                    agg[d] += h[s] + edge_feat[j]
                    cnt[d] += 1
            cnt = cnt.clamp(min=1).unsqueeze(-1)
            agg = agg / cnt
            h = self.norm(self.gru(agg, h))

        return self.fc(torch.cat([h.mean(0), h.max(0)[0]], -1)).squeeze(-1)


class GNNScanner:
    """Production scanner using trained GNN model."""

    def __init__(
        self, model_path: str = "data/best_model_v2.pt", threshold: float = 0.5, device: str = "cpu"
    ):
        self.device = device
        self.threshold = threshold

        self.model = Detector(dim=128)

        if Path(model_path).exists():
            ckpt = torch.load(model_path, weights_only=False, map_location=device)
            self.model.load_state_dict(ckpt["model"])
            print(f"Loaded model from {model_path}")
            print(f"Model F1: {ckpt.get('f1', 'unknown'):.1%}")
        else:
            print(f"Warning: Model not found at {model_path}")

        self.model.to(device)
        self.model.eval()

    def scan_topology(self, topology: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a topology for vulnerabilities."""
        tensors = self._topology_to_tensors(topology)

        with torch.no_grad():
            logits = self.model(
                tensors["node_types"],
                tensors["node_trust"],
                tensors["edge_src"],
                tensors["edge_dst"],
                tensors["edge_flows"],
            )
            prob = torch.sigmoid(logits).item()

        return {
            "vulnerable": prob > self.threshold,
            "confidence": prob,
            "threshold": self.threshold,
            "severity": self._get_severity(prob),
        }

    def scan_json(self, json_path: str) -> Dict[str, Any]:
        """Scan a JSON topology file"""
        with open(json_path) as f:
            topology = json.load(f)
        return self.scan_topology(topology)

    def _topology_to_tensors(self, topology: Dict) -> Dict:
        nodes = topology.get("nodes", [])
        edges = topology.get("edges", [])

        node_types = [NODE_TYPE_MAP.get(n.get("type", ""), 0) for n in nodes]
        node_trust = [TRUST_MAP.get(n.get("trust_boundary", ""), 3) for n in nodes]

        node_id_to_idx = {n["id"]: i for i, n in enumerate(nodes)}

        edge_src = []
        edge_dst = []
        edge_flows = []

        for e in edges:
            if e.get("from") in node_id_to_idx and e.get("to") in node_id_to_idx:
                edge_src.append(node_id_to_idx[e["from"]])
                edge_dst.append(node_id_to_idx[e["to"]])
                # Accept both "flow" and "data_flow" keys
                flow = e.get("data_flow") or e.get("flow") or ""
                edge_flows.append(FLOW_MAP.get(flow, 0))

        max_n, max_e = 32, 64
        while len(node_types) < max_n:
            node_types.append(0)
            node_trust.append(0)
        while len(edge_src) < max_e:
            edge_src.append(0)
            edge_dst.append(0)
            edge_flows.append(0)

        return {
            "node_types": torch.tensor(node_types[:max_n], dtype=torch.long),
            "node_trust": torch.tensor(node_trust[:max_n], dtype=torch.long),
            "edge_src": torch.tensor(edge_src[:max_e], dtype=torch.long),
            "edge_dst": torch.tensor(edge_dst[:max_e], dtype=torch.long),
            "edge_flows": torch.tensor(edge_flows[:max_e], dtype=torch.long),
        }

    def _get_severity(self, prob: float) -> str:
        if prob > 0.8:
            return "critical"
        elif prob > 0.6:
            return "high"
        elif prob > 0.4:
            return "medium"
        elif prob > 0.2:
            return "low"
        else:
            return "info"


if __name__ == "__main__":
    print("=== TESSERA GNN Scanner ===")

    scanner = GNNScanner("data/best_model_v2.pt")

    # Test benign
    benign = {
        "nodes": [
            {"id": "u1", "type": "user", "trust_boundary": "external"},
            {"id": "a1", "type": "api", "trust_boundary": "internal"},
            {"id": "d1", "type": "database", "trust_boundary": "internal"},
        ],
        "edges": [
            {"from": "u1", "to": "a1", "data_flow": "api"},
            {"from": "a1", "to": "d1", "data_flow": "read_write"},
        ],
    }
    r1 = scanner.scan_topology(benign)
    print(f"Benign: {r1}")

    # Test attack
    attack = {
        "nodes": [
            {"id": "u1", "type": "user", "trust_boundary": "external"},
            {"id": "llm1", "type": "llm", "trust_boundary": "internal"},
            {"id": "rag1", "type": "rag_corpus", "trust_boundary": "user_controlled"},
            {"id": "t1", "type": "tool", "trust_boundary": "external"},
        ],
        "edges": [
            {"from": "u1", "to": "llm1", "data_flow": "inference"},
            {"from": "llm1", "to": "rag1", "data_flow": "retrieval"},
            {"from": "rag1", "to": "t1", "data_flow": "tool_call"},
        ],
    }
    r2 = scanner.scan_topology(attack)
    print(f"Attack: {r2}")
    print("\nScanner ready!")
