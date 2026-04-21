"""
TESSERA RDT Scanner Integration.
Hooks RDT model into existing TESSERA scanner pipeline.
"""

import torch
from typing import Optional
from pathlib import Path
import json

from tessera.rdt.config import RDTConfig, rdt_small
from tessera.rdt.model import TesseraRDT
from tessera.rdt.data_pipeline import (
    NODE_TYPE_TO_IDX,
    TRUST_TO_IDX,
    DATA_FLOW_TO_IDX,
    VULN_CLASS_TO_IDX,
    IDX_TO_VULN_CLASS,
)
from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary, DataFlow
from tessera.core.findings.models import Finding, FindingSeverity, FailureType


class RDTScanner:
    """
    RDT-powered scanner for compound attack detection.

    Integrates with existing TESSERA pipeline.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        config: Optional[RDTConfig] = None,
        device: str = "cpu",
    ):
        self.device = device
        self.config = config or rdt_small()

        # Load model
        if model_path and Path(model_path).exists():
            self.model = self._load_model(model_path)
        else:
            self.model = TesseraRDT(self.config)

        self.model.to(device)
        self.model.eval()

        # Confidence threshold
        self.threshold = 0.5

    def _load_model(self, path: str) -> TesseraRDT:
        return torch.load(path, map_location=self.device)

    def _encode_topology(self, graph: Graph):
        """Encode TESSERA Graph to model inputs."""
        node_list = list(graph.nodes.values())
        num_nodes = len(node_list)

        # Node encoding
        node_types = []
        node_trust = []

        for node in node_list:
            type_idx = NODE_TYPE_TO_IDX.get(node.type, 6)
            trust_idx = TRUST_TO_IDX.get(node.trust_boundary.value, 4)
            node_types.append(type_idx)
            node_trust.append(trust_idx)

        # Edge encoding
        edge_flows = []
        edge_trust = []
        edge_src = []
        edge_dst = []

        node_ids = {n.id: i for i, n in enumerate(node_list)}

        for edge in graph.edges:
            edge_flows.append(DATA_FLOW_TO_IDX.get(edge.data_flow.value, 3))
            edge_trust.append(TRUST_TO_IDX.get(edge.trust_boundary.value, 4))
            edge_src.append(node_ids.get(edge.from_node, 0))
            edge_dst.append(node_ids.get(edge.to_node, 0))

        return {
            "node_types": torch.tensor([node_types], dtype=torch.long),
            "node_trust": torch.tensor([node_trust], dtype=torch.long),
            "edge_flows": torch.tensor([edge_flows], dtype=torch.long),
            "edge_trust": torch.tensor([edge_trust], dtype=torch.long),
            "edge_src": torch.tensor(edge_src, dtype=torch.long),
            "edge_dst": torch.tensor(edge_dst, dtype=torch.long),
        }

    def scan(self, graph: Graph, num_loops: Optional[int] = None) -> list[Finding]:
        """
        Scan topology for vulnerability patterns.

        Args:
            graph: TESSERA Graph
            num_loops: Recurrent loops (default: config.default_loops)

        Returns:
            List of findings
        """
        if not graph.nodes:
            return []

        # Encode
        inputs = self._encode_topology(graph)

        # Move to device
        for k, v in inputs.items():
            inputs[k] = v.to(self.device)

        # Inference
        with torch.no_grad():
            logits, loops, aux_loss = self.model(
                inputs["node_types"],
                inputs["node_trust"],
                inputs["edge_flows"],
                inputs["edge_trust"],
                inputs["edge_src"],
                inputs["edge_dst"],
                num_loops=num_loops or self.config.default_loops,
            )

            probs = torch.softmax(logits, dim=-1)
            preds = probs.argmax(dim=-1)

        # Convert to findings
        findings = []
        node_list = list(graph.nodes.values())

        for i, pred in enumerate(preds[0]):
            if i >= len(node_list):
                break

            node = node_list[i]
            prob = probs[0, i, pred.item()].item()

            if prob >= self.threshold and pred.item() > 0:
                vuln_class = IDX_TO_VULN_CLASS[pred.item()]

                # Map to TESSERA severity
                severity_map = {
                    "benign": FindingSeverity.INFO,
                    "suspicious": FindingSeverity.MEDIUM,
                    "high": FindingSeverity.HIGH,
                    "critical": FindingSeverity.CRITICAL,
                }

                category_map = {
                    "suspicious": FailureType.COMPOUND_CHAIN,
                    "high": FailureType.COMPOUND_CHAIN,
                    "critical": FailureType.TRUST_BOUNDARY_BYPASS,
                }

                finding = Finding(
                    finding_id=f"RDT-{node.id}",
                    scan_id="rdt-scan",
                    severity=severity_map.get(vuln_class, FindingSeverity.MEDIUM),
                    failure_type=category_map.get(vuln_class, FailureType.COMPOUND_CHAIN),
                    evidence={
                        "description": f"Vulnerability detected in {node.type}",
                        "confidence": prob,
                    },
                )
                findings.append(finding)

        return findings

    def scan_file(self, yaml_path: str, **kwargs) -> list[Finding]:
        """Scan from YAML file."""
        from tessera.core.topology.loader import load_topology

        graph = load_topology(yaml_path)
        return self.scan(graph, **kwargs)


def load_rdt_scanner(
    model_path: Optional[str] = None,
    config: Optional[RDTConfig] = None,
) -> RDTScanner:
    """Load RDT scanner with optional pretrained model."""
    return RDTScanner(model_path=model_path, config=config)


if __name__ == "__main__":
    print("=== RDT Scanner Test ===")

    # Create demo topology
    graph = Graph(
        system="test_agent",
        nodes={
            "intake": Node(id="intake", type="llm", trust_boundary=TrustBoundary.USER_CONTROLLED),
            "rag": Node(
                id="rag", type="rag_corpus", trust_boundary=TrustBoundary.PARTIALLY_TRUSTED
            ),
            "tool": Node(id="tool", type="tool", trust_boundary=TrustBoundary.INTERNAL),
        },
        edges=[
            Edge(
                from_node="intake",
                to_node="rag",
                data_flow=DataFlow.RETRIEVAL,
                trust_boundary=TrustBoundary.EXTERNAL,
            ),
            Edge(
                from_node="intake",
                to_node="tool",
                data_flow=DataFlow.TOOL_CALL,
                trust_boundary=TrustBoundary.EXTERNAL,
            ),
        ],
    )

    # Create scanner
    scanner = RDTScanner()

    # Scan
    findings = scanner.scan(graph)

    print(f"Found {len(findings)} findings")
    for f in findings:
        print(f"  - {f.id}: {f.severity} ({f.description})")

    print("=== Scanner OK ===")
