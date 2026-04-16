from dataclasses import dataclass
from typing import Optional
import json
import numpy as np
from tessera.classifier.gnn.data import (
    TopologyGraph,
    NodeType,
    EdgeType,
    TrustLevel,
    GraphNode,
    GraphEdge,
)
from tessera.classifier.gnn.model import CompoundFailureClassifier, GNNConfig


@dataclass
class TrainingSample:
    graph: TopologyGraph
    label: int
    metadata: dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class GNNTrainingPipeline:
    def __init__(self, classifier: Optional[CompoundFailureClassifier] = None):
        self.classifier = classifier or CompoundFailureClassifier()
        self.training_data: list[TrainingSample] = []

    def add_sample(
        self,
        graph: TopologyGraph,
        label: int,
        metadata: Optional[dict] = None,
    ) -> None:
        self.training_data.append(TrainingSample(graph, label, metadata or {}))

    def create_sample_from_swarm_result(
        self,
        topology_paths: list[list[str]],
        discoveries: list[dict],
    ) -> TopologyGraph:
        graph = TopologyGraph()

        for path in topology_paths:
            for node_id in path:
                if node_id not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=node_id,
                            node_type=NodeType.LLM if "llm" in node_id.lower() else NodeType.TOOL,
                            trust=TrustLevel.TRUSTED,
                        )
                    )

            for i in range(len(path) - 1):
                graph.add_edge(
                    GraphEdge(
                        from_node=path[i],
                        to_node=path[i + 1],
                        edge_type=EdgeType.PROMPT,
                    )
                )

        for discovery in discoveries:
            path = discovery.get("path", [])
            if path:
                for node_id in path:
                    if node_id in graph.nodes:
                        graph.nodes[node_id].trust = TrustLevel.UNTRUSTED

        return graph

    def train(self, epochs: int = 100) -> dict:
        if not self.training_data:
            return {"error": "No training data"}

        features = []
        adj_matrices = []
        labels = []

        for sample in self.training_data:
            feat = sample.graph.to_feature_matrix()
            n = len(sample.graph.nodes)
            adj = np.zeros((n, n))
            for edge in sample.graph.edges:
                try:
                    node_ids = list(sample.graph.nodes.keys())
                    i = node_ids.index(edge.from_node)
                    j = node_ids.index(edge.to_node)
                    adj[i, j] = 1
                except (ValueError, IndexError):
                    pass

            features.append(feat)
            adj_matrices.append(adj)
            labels.append(sample.label)

        result = self.classifier.train(features, adj_matrices, labels, epochs)

        result["samples_trained"] = len(self.training_data)
        return result

    def predict(self, graph: TopologyGraph) -> dict:
        features = graph.to_feature_matrix()
        n = len(graph.nodes)
        adj = np.zeros((n, n))
        for edge in graph.edges:
            try:
                node_ids = list(graph.nodes.keys())
                i = node_ids.index(edge.from_node)
                j = node_ids.index(edge.to_node)
                adj[i, j] = 1
            except (ValueError, IndexError):
                pass

        result = self.classifier.classify(features, adj)
        # Add class_index for evaluation
        classes = ["safe", "atomic_injection", "chain_exploitation", "exfiltration"]
        for pred in result.get("predictions", []):
            pred["class_index"] = classes.index(pred["class"])
        return result

    def save(self, path: str) -> None:
        pass

    def load(self, path: str) -> None:
        pass


def create_pipeline() -> GNNTrainingPipeline:
    return GNNTrainingPipeline()
