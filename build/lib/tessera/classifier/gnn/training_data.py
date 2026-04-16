"""Training data generator for GNN classifier."""

import random
from tessera.classifier.gnn.data import (
    TopologyGraph,
    GraphNode,
    GraphEdge,
    EdgeType,
    TrustLevel as GNNTrustLevel,
)
from tessera.topology.models import NodeType, TrustBoundary


class TrainingDataGenerator:
    """Generate synthetic training data for GNN cold-start."""

    LABEL_SAFE = 0
    LABEL_ATOMIC = 1
    LABEL_CHAIN = 2
    LABEL_EXFIL = 3

    def __init__(self):
        self.samples = []

    def _to_gnn_trust(self, trust: TrustBoundary) -> GNNTrustLevel:
        """Convert topology trust to GNN trust."""
        mapping = {
            TrustBoundary.TRUSTED: GNNTrustLevel.TRUSTED,
            TrustBoundary.PARTIALLY_TRUSTED: GNNTrustLevel.PARTIALLY_TRUSTED,
            TrustBoundary.USER_CONTROLLED: GNNTrustLevel.UNTRUSTED,
            TrustBoundary.INTERNAL_TRUSTED: GNNTrustLevel.TRUSTED,
        }
        return mapping.get(trust, GNNTrustLevel.TRUSTED)

    def generate_compound_failure_samples(self, count: int = 100) -> list[dict]:
        """Generate compound failure chain samples."""
        samples = []

        templates = [
            {
                "nodes": [
                    ("rag_corpus", NodeType.RAG, TrustBoundary.USER_CONTROLLED),
                    ("tool_crm", NodeType.TOOL, TrustBoundary.TRUSTED),
                ],
                "edges": [
                    ("rag_corpus", "tool_crm", EdgeType.TOOL_CALL),
                ],
                "label": self.LABEL_CHAIN,
            },
            {
                "nodes": [
                    ("memory_store", NodeType.MEMORY, TrustBoundary.USER_CONTROLLED),
                    ("llm_main", NodeType.LLM, TrustBoundary.TRUSTED),
                ],
                "edges": [
                    ("memory_store", "llm_main", EdgeType.PROMPT),
                ],
                "label": self.LABEL_CHAIN,
            },
            {
                "nodes": [
                    ("api_gateway", NodeType.API, TrustBoundary.USER_CONTROLLED),
                    ("llm_main", NodeType.LLM, TrustBoundary.TRUSTED),
                    ("tool_admin", NodeType.TOOL, TrustBoundary.TRUSTED),
                ],
                "edges": [
                    ("api_gateway", "llm_main", EdgeType.PROMPT),
                    ("llm_main", "tool_admin", EdgeType.TOOL_CALL),
                ],
                "label": self.LABEL_CHAIN,
            },
            {
                "nodes": [
                    ("rag_docs", NodeType.RAG, TrustBoundary.USER_CONTROLLED),
                    ("memory", NodeType.MEMORY, TrustBoundary.USER_CONTROLLED),
                    ("llm", NodeType.LLM, TrustBoundary.TRUSTED),
                ],
                "edges": [
                    ("rag_docs", "memory", EdgeType.MEMORY_WRITE),
                    ("memory", "llm", EdgeType.PROMPT),
                ],
                "label": self.LABEL_CHAIN,
            },
        ]

        for i in range(count):
            template = random.choice(templates)
            graph = TopologyGraph()

            for node_id, node_type, trust in template["nodes"]:
                graph.add_node(
                    GraphNode(
                        id=node_id,
                        node_type=node_type,
                        trust=self._to_gnn_trust(trust),
                    )
                )

            for from_node, to_node, edge_type in template["edges"]:
                graph.add_edge(
                    GraphEdge(
                        from_node=from_node,
                        to_node=to_node,
                        edge_type=edge_type,
                        trust=GNNTrustLevel.UNTRUSTED,
                    )
                )

            samples.append(
                {
                    "graph": graph,
                    "label": template["label"],
                }
            )

        return samples

    def generate_safe_samples(self, count: int = 100) -> list[dict]:
        """Generate safe samples (no indicators)."""
        samples = []

        configs = [
            [
                ("user_input", NodeType.USER_INPUT, TrustBoundary.USER_CONTROLLED),
                ("llm", NodeType.LLM, TrustBoundary.TRUSTED),
            ],
            [
                ("user_input", NodeType.USER_INPUT, TrustBoundary.USER_CONTROLLED),
                ("rag", NodeType.RAG, TrustBoundary.TRUSTED),
                ("llm", NodeType.LLM, TrustBoundary.TRUSTED),
            ],
            [
                ("llm", NodeType.LLM, TrustBoundary.TRUSTED),
                ("output", NodeType.MODEL, TrustBoundary.TRUSTED),
            ],
        ]

        for i in range(count):
            config = random.choice(configs)
            graph = TopologyGraph()

            for node_id, node_type, trust in config:
                graph.add_node(
                    GraphNode(
                        id=node_id,
                        node_type=node_type,
                        trust=self._to_gnn_trust(trust),
                    )
                )

            for j in range(len(config) - 1):
                graph.add_edge(
                    GraphEdge(
                        from_node=config[j][0],
                        to_node=config[j + 1][0],
                        edge_type=EdgeType.PROMPT,
                        trust=GNNTrustLevel.TRUSTED,
                    )
                )

            samples.append(
                {
                    "graph": graph,
                    "label": self.LABEL_SAFE,
                }
            )

        return samples

    def generate_atomic_samples(self, count: int = 50) -> list[dict]:
        """Generate atomic injection samples."""
        samples = []

        for i in range(count):
            graph = TopologyGraph()

            graph.add_node(
                GraphNode(
                    id="user_input",
                    node_type=NodeType.USER_INPUT,
                    trust=GNNTrustLevel.UNTRUSTED,
                )
            )
            graph.add_node(
                GraphNode(
                    id="llm",
                    node_type=NodeType.LLM,
                    trust=GNNTrustLevel.TRUSTED,
                )
            )

            graph.add_edge(
                GraphEdge(
                    from_node="user_input",
                    to_node="llm",
                    edge_type=EdgeType.PROMPT,
                    trust=GNNTrustLevel.UNTRUSTED,
                )
            )

            samples.append(
                {
                    "graph": graph,
                    "label": self.LABEL_ATOMIC,
                }
            )

        return samples

    def generate_exfil_samples(self, count: int = 50) -> list[dict]:
        """Generate data exfiltration samples."""
        samples = []

        for i in range(count):
            graph = TopologyGraph()

            graph.add_node(
                GraphNode(
                    id="llm",
                    node_type=NodeType.LLM,
                    trust=GNNTrustLevel.TRUSTED,
                )
            )
            graph.add_node(
                GraphNode(
                    id="api",
                    node_type=NodeType.API,
                    trust=GNNTrustLevel.UNTRUSTED,
                )
            )

            graph.add_edge(
                GraphEdge(
                    from_node="llm",
                    to_node="api",
                    edge_type=EdgeType.TOOL_CALL,
                    trust=GNNTrustLevel.UNTRUSTED,
                )
            )

            samples.append(
                {
                    "graph": graph,
                    "label": self.LABEL_EXFIL,
                }
            )

        return samples

    def generate_all(self, counts: dict | None = None) -> list[dict]:
        """Generate complete training set."""
        if counts is None:
            counts = {"safe": 100, "compound": 100, "atomic": 50, "exfil": 50}

        all_samples = []
        all_samples.extend(self.generate_safe_samples(counts.get("safe", 100)))
        all_samples.extend(self.generate_compound_failure_samples(counts.get("compound", 100)))
        all_samples.extend(self.generate_atomic_samples(counts.get("atomic", 50)))
        all_samples.extend(self.generate_exfil_samples(counts.get("exfil", 50)))

        random.shuffle(all_samples)
        return all_samples


def create_training_dataset() -> tuple[list, list, list, list]:
    """Create train/test splits for GNN training."""
    gen = TrainingDataGenerator()
    samples = gen.generate_all()

    random.shuffle(samples)

    n = len(samples)
    split = int(n * 0.8)

    train = samples[:split]
    test = samples[split:]

    return train, test
