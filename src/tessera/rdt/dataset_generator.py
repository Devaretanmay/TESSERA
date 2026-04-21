"""
Dataset Generator for TESSERA RDT - Synthetic attack graph generation.
Generates topologies with CFPE vulnerability labels for training.
"""

import random
import json
import yaml
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum
from pathlib import Path


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------


class NodeType(str, Enum):
    LLM = "llm"
    MODEL = "model"
    RAG_CORPUS = "rag_corpus"
    TOOL = "tool"
    MEMORY_STORE = "memory_store"
    DATABASE = "database"
    API = "api"
    FILESYSTEM = "filesystem"
    USER = "user"
    AGENT = "agent"
    EXTERNAL_SERVICE = "external_service"
    CACHE = "cache"
    QUEUE = "queue"
    LOGGER = "logger"
    AUTH = "auth"


class TrustBoundary(str, Enum):
    PUBLIC = "public"
    EXTERNAL = "external"
    USER_CONTROLLED = "user_controlled"
    PARTIALLY_TRUSTED = "partially_trusted"
    INTERNAL = "internal"
    PRIVILEGED = "privileged"


class DataFlow(str, Enum):
    RETRIEVAL = "retrieval"
    TOOL_CALL = "tool_call"
    READ_WRITE = "read_write"
    API = "api"
    INFERENCE = "inference"
    SIGNAL = "signal"


class VulnClass(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"


# ----------------------------------------------------------------------
# Graph Grammar
# ----------------------------------------------------------------------


@dataclass
class AttackPattern:
    """Defines a CFPE attack pattern."""

    name: str
    pattern_id: str
    node_types: list[str]
    edge_flows: list[str]
    trust_crossing: bool = False
    severity: str = "high"


# Known CFPE patterns from TESSERA
ATTACK_PATTERNS = [
    AttackPattern(
        name="RAG to Tool",
        pattern_id="CFPE-0001",
        node_types=["llm", "rag_corpus", "tool"],
        edge_flows=["retrieval", "tool_call"],
        severity="high",
    ),
    AttackPattern(
        name="Memory Poisoning",
        pattern_id="CFPE-0002",
        node_types=["llm", "memory_store"],
        edge_flows=["read_write"],
        trust_crossing=True,
        severity="critical",
    ),
    AttackPattern(
        name="Trust Boundary Bypass",
        pattern_id="CFPE-0004",
        node_types=["llm", "tool", "api"],
        edge_flows=["api"],
        trust_crossing=True,
        severity="high",
    ),
    AttackPattern(
        name="External Data Exfiltration",
        pattern_id="CFPE-0003",
        node_types=["llm", "external_service", "api"],
        edge_flows=["api", "signal"],
        trust_crossing=True,
        severity="critical",
    ),
    AttackPattern(
        name="Tool Chain Escalation",
        pattern_id="CFPE-0005",
        node_types=["llm", "tool", "tool", "database"],
        edge_flows=["tool_call", "read_write"],
        severity="high",
    ),
]


# ----------------------------------------------------------------------
# Data Classes
# ----------------------------------------------------------------------


@dataclass
class Node:
    id: str
    type: str
    trust_boundary: str = "internal"
    provider: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class Edge:
    from_node: str
    to_node: str
    data_flow: str
    trust_boundary: str = "internal"


@dataclass
class Topology:
    system: str
    version: str = "1.0.0"
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)


@dataclass
class LabeledGraph:
    """Graph with vulnerability labels."""

    topology: Topology
    vuln_class: str = "benign"
    vulnerable_edges: list[str] = field(default_factory=list)  # edge IDs like "node_a->node_b"
    pattern_id: Optional[str] = None
    attack_path: list[str] = field(default_factory=list)  # ordered list of edge IDs


# ----------------------------------------------------------------------
# Graph Generator
# ----------------------------------------------------------------------


class AttackGraphGenerator:
    """
    Generates synthetic attack graphs for training.

    Grammar:
    - Node types: LLM, tool, rag_corpus, memory_store, database, api, etc.
    - Data flows: retrieval, tool_call, read_write, api, inference, signal
    - Trust boundaries: public, external, user_controlled, partially_trusted, internal, privileged

    Attack patterns:
    - RAG → Tool (CFPE-0001)
    - Memory poisoning (CFPE-0002)
    - Trust boundary bypass (CFPE-0004)
    """

    def __init__(
        self,
        positive_ratio: float = 0.1,
        min_nodes: int = 3,
        max_nodes: int = 15,
        seed: Optional[int] = None,
    ):
        self.positive_ratio = positive_ratio
        self.min_nodes = min_nodes
        self.max_nodes = max_nodes

        if seed is not None:
            random.seed(seed)

        self.node_counter = 0
        self.edge_counter = 0

    def _new_node_id(self) -> str:
        self.node_counter += 1
        return f"node_{self.node_counter}"

    def _new_edge_id(self) -> str:
        self.edge_counter += 1
        return f"edge_{self.edge_counter}"

    def _random_node_type(self) -> str:
        """Most common node types weighted by frequency."""
        weights = {
            "llm": 20,
            "tool": 25,
            "api": 15,
            "rag_corpus": 10,
            "memory_store": 8,
            "database": 12,
            "user": 5,
            "external_service": 5,
        }
        return random.choices(list(weights.keys()), weights=list(weights.values()))[0]

    def _random_trust_boundary(self) -> str:
        """Weighted trust boundaries."""
        weights = {
            "internal": 40,
            "user_controlled": 20,
            "partially_trusted": 15,
            "external": 10,
            "public": 10,
            "privileged": 5,
        }
        return random.choices(list(weights.keys()), weights=list(weights.values()))[0]

    def _random_data_flow(self) -> str:
        """Weighted data flows."""
        weights = {
            "api": 30,
            "tool_call": 20,
            "retrieval": 15,
            "read_write": 15,
            "inference": 10,
            "signal": 10,
        }
        return random.choices(list(weights.keys()), weights=list(weights.values()))[0]

    def _generate_benign_graph(self) -> Topology:
        """Generate a benign graph without attack patterns."""
        num_nodes = random.randint(self.min_nodes, self.max_nodes)

        nodes = []
        edges = []

        # Generate nodes
        for i in range(num_nodes):
            node = Node(
                id=self._new_node_id(),
                type=self._random_node_type(),
                trust_boundary=self._random_trust_boundary(),
            )
            nodes.append(node)

        # Generate edges (random connections)
        num_edges = random.randint(num_nodes // 2, num_nodes)

        for _ in range(num_edges):
            from_node = random.choice(nodes).id
            to_node = random.choice(nodes).id

            if from_node != to_node:
                edge = Edge(
                    from_node=from_node,
                    to_node=to_node,
                    data_flow=self._random_data_flow(),
                    trust_boundary=self._random_trust_boundary(),
                )
                edges.append(edge)

        return Topology(
            system=f"graph_{random.randint(1000, 9999)}",
            nodes=nodes,
            edges=edges,
        )

    def _inject_attack_pattern(self, graph: Topology, pattern: AttackPattern) -> LabeledGraph:
        """Inject an attack pattern into the graph."""
        # Find or create nodes matching the pattern
        nodes_by_type: dict[str, list[Node]] = {}
        for node in graph.nodes:
            nodes_by_type.setdefault(node.type, []).append(node)

        # Find matching nodes, create if needed
        pattern_nodes = []
        for node_type in pattern.node_types:
            if node_type in nodes_by_type and nodes_by_type[node_type]:
                node = random.choice(nodes_by_type[node_type])
                pattern_nodes.append(node)
            else:
                # Create missing node
                new_node = Node(
                    id=self._new_node_id(),
                    type=node_type,
                    trust_boundary="internal",
                )
                graph.nodes.append(new_node)
                pattern_nodes.append(new_node)

        # Create attack edges
        vulnerable_edges = []

        for i in range(len(pattern_nodes) - 1):
            from_node = pattern_nodes[i]
            to_node = pattern_nodes[i + 1]

            edge = Edge(
                from_node=from_node.id,
                to_node=to_node.id,
                data_flow=pattern.edge_flows[i] if i < len(pattern.edge_flows) else "api",
                trust_boundary="external" if pattern.trust_crossing else "internal",
            )
            graph.edges.append(edge)

            vulnerable_edges.append(f"{from_node.id}->{to_node.id}")

        # Set severity based on pattern
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "suspicious",
            "low": "suspicious",
        }
        vuln_class = severity_map.get(pattern.severity, "suspicious")

        return LabeledGraph(
            topology=graph,
            vuln_class=vuln_class,
            vulnerable_edges=vulnerable_edges,
            pattern_id=pattern.pattern_id,
            attack_path=vulnerable_edges,
        )

    def generate(self) -> LabeledGraph:
        """Generate a labeled graph."""
        is_attack = random.random() < self.positive_ratio

        if is_attack:
            # Generate and inject attack pattern
            graph = self._generate_benign_graph()
            pattern = random.choice(ATTACK_PATTERNS)
            labeled = self._inject_attack_pattern(graph, pattern)
            return labeled
        else:
            # Generate benign graph
            graph = self._generate_benign_graph()
            return LabeledGraph(
                topology=graph,
                vuln_class="benign",
                vulnerable_edges=[],
            )

    def generate_batch(self, num_graphs: int) -> list[LabeledGraph]:
        """Generate multiple graphs."""
        return [self.generate() for _ in range(num_graphs)]


# ----------------------------------------------------------------------
# Export Functions
# ----------------------------------------------------------------------


def topology_to_yaml(topology: Topology) -> dict:
    """Convert topology to dictionary for YAML export."""
    return {
        "system": topology.system,
        "version": topology.version,
        "nodes": [
            {
                "id": n.id,
                "type": n.type,
                "trust_boundary": n.trust_boundary,
            }
            for n in topology.nodes
        ],
        "edges": [
            {
                "from": e.from_node,
                "to": e.to_node,
                "data_flow": e.data_flow,
                "trust_boundary": e.trust_boundary,
            }
            for e in topology.edges
        ],
    }


def labeled_graph_to_json(labeled: LabeledGraph) -> dict:
    """Convert labeled graph to JSON-serializable dict."""
    data = topology_to_yaml(labeled.topology)
    data.update(
        {
            "vuln_class": labeled.vuln_class,
            "vulnerable_edges": labeled.vulnerable_edges,
            "pattern_id": labeled.pattern_id,
        }
    )
    return data


def save_dataset(
    labeled_graphs: list[LabeledGraph],
    output_path: str,
    split_ratios: tuple[float, float, float] = (0.8, 0.1, 0.1),
) -> dict[str, list]:
    """
    Save dataset to JSONL files.

    Returns file paths for train/val/test splits.
    """
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Shuffle
    random.shuffle(labeled_graphs)

    # Split
    n = len(labeled_graphs)
    n_train = int(n * split_ratios[0])
    n_val = int(n * split_ratios[1])

    train_graphs = labeled_graphs[:n_train]
    val_graphs = labeled_graphs[n_train : n_train + n_val]
    test_graphs = labeled_graphs[n_train + n_val :]

    # Save each split
    splits = {
        "train": train_graphs,
        "val": val_graphs,
        "test": test_graphs,
    }

    file_paths = {}

    for split_name, graphs in splits.items():
        file_path = output_dir / f"{split_name}.jsonl"
        with open(file_path, "w") as f:
            for labeled in graphs:
                json.dump(labeled_graph_to_json(labeled), f)
                f.write("\n")
        file_paths[split_name] = str(file_path)

    # Save metadata
    meta = {
        "total": n,
        "train": len(train_graphs),
        "val": len(val_graphs),
        "test": len(test_graphs),
        "positive_ratio": sum(1 for g in labeled_graphs if g.vuln_class != "benign") / n,
        "splits": split_ratios,
    }

    meta_path = output_dir / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    file_paths["metadata"] = str(meta_path)

    return file_paths


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # Generate dataset
    print("Generating attack graph dataset...")

    generator = AttackGraphGenerator(
        positive_ratio=0.1,  # 10% positive
        min_nodes=3,
        max_nodes=15,
        seed=42,
    )

    # Generate 10K graphs
    graphs = generator.generate_batch(10_000)

    # Save dataset
    file_paths = save_dataset(graphs, "data/attack_graphs.jsonl")

    print(f"Dataset saved to:")
    for name, path in file_paths.items():
        print(f"  {name}: {path}")

    # Print stats
    with open(file_paths["metadata"]) as f:
        meta = json.load(f)

    print(f"\nDataset statistics:")
    print(f"  Total graphs: {meta['total']:,}")
    print(f"  Train: {meta['train']:,}")
    print(f"  Val: {meta['val']:,}")
    print(f"  Test: {meta['test']:,}")
    print(f"  Positive ratio: {meta['positive_ratio']:.1%}")
