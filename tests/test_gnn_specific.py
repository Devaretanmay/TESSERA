import numpy as np
from tessera.classifier.gnn.model import GraphSAGEModel
from tessera.classifier.gnn.data import (
    TopologyGraph,
    NodeType,
    TrustLevel,
    GraphNode,
    GraphEdge,
    EdgeType,
)


def test_gnn_represents_compound_patterns():
    model = GraphSAGEModel()

    # Create benign graph: simple LLM -> tool flow
    benign_graph = TopologyGraph()
    benign_graph.add_node(GraphNode("llm", NodeType.LLM, TrustLevel.TRUSTED))
    benign_graph.add_node(GraphNode("tool", NodeType.TOOL, TrustLevel.TRUSTED))
    benign_graph.add_edge(GraphEdge("llm", "tool", EdgeType.PROMPT))

    # Create malicious graph: untrusted input -> compromised LLM -> tool
    malicious_graph = TopologyGraph()
    malicious_graph.add_node(GraphNode("input", NodeType.USER_INPUT, TrustLevel.UNTRUSTED))
    malicious_graph.add_node(GraphNode("llm", NodeType.LLM, TrustLevel.UNTRUSTED))
    malicious_graph.add_node(GraphNode("tool", NodeType.TOOL, TrustLevel.TRUSTED))
    malicious_graph.add_edge(GraphEdge("input", "llm", EdgeType.PROMPT))
    malicious_graph.add_edge(GraphEdge("llm", "tool", EdgeType.PROMPT))

    # Get embeddings
    benign_feat = benign_graph.to_feature_matrix()
    benign_adj = np.zeros((2, 2))
    benign_adj[0, 1] = 1

    malicious_feat = malicious_graph.to_feature_matrix()
    malicious_adj = np.zeros((3, 3))
    malicious_adj[0, 1] = 1
    malicious_adj[1, 2] = 1

    benign_emb = model.predict(benign_feat, benign_adj)
    malicious_emb = model.predict(malicious_feat, malicious_adj)

    # Embeddings should be meaningfully different
    distance = np.linalg.norm(benign_emb.mean(axis=0) - malicious_emb.mean(axis=0))
    assert distance > 0.1, f"Expected meaningful difference in embeddings, got distance {distance}"

    # Both should produce reasonable normalized embeddings
    assert np.all(np.isfinite(benign_emb))
    assert np.all(np.isfinite(malicious_emb))


def test_gnn_produces_different_embeddings_for_different_graphs():
    from tessera.classifier.gnn.model import GraphSAGEModel

    model = GraphSAGEModel()

    # Safe graph: LLM -> tool (no compromise)
    safe_graph = TopologyGraph()
    safe_graph.add_node(GraphNode("llm", NodeType.LLM, TrustLevel.TRUSTED))
    safe_graph.add_node(GraphNode("tool", NodeType.TOOL, TrustLevel.TRUSTED))
    safe_graph.add_edge(GraphEdge("llm", "tool", EdgeType.PROMPT))

    # Compound graph: input -> llm -> tool with compromised llm
    compound_graph = TopologyGraph()
    compound_graph.add_node(GraphNode("input", NodeType.USER_INPUT, TrustLevel.UNTRUSTED))
    compound_graph.add_node(GraphNode("llm", NodeType.LLM, TrustLevel.UNTRUSTED))
    compound_graph.add_node(GraphNode("tool", NodeType.TOOL, TrustLevel.TRUSTED))
    compound_graph.add_edge(GraphEdge("input", "llm", EdgeType.PROMPT))
    compound_graph.add_edge(GraphEdge("llm", "tool", EdgeType.PROMPT))

    # Get embeddings from GNN
    safe_feat = safe_graph.to_feature_matrix()
    safe_adj = np.zeros((2, 2))
    safe_adj[0, 1] = 1  # llm -> tool

    compound_feat = compound_graph.to_feature_matrix()
    compound_adj = np.zeros((3, 3))
    compound_adj[0, 1] = 1  # input -> llm
    compound_adj[1, 2] = 1  # llm -> tool

    safe_emb = model.predict(safe_feat, safe_adj)
    compound_emb = model.predict(compound_feat, compound_adj)

    # The GNN should produce different embeddings for different graph structures
    # Compare mean embeddings across nodes
    safe_mean = safe_emb.mean(axis=0)
    compound_mean = compound_emb.mean(axis=0)

    # Embeddings should be meaningfully different
    distance = np.linalg.norm(safe_mean - compound_mean)
    assert distance > 0.01, (
        f"Expected different embeddings for safe vs compound graphs, distance={distance}"
    )

    # Both should be valid embeddings
    assert np.all(np.isfinite(safe_emb))
    assert np.all(np.isfinite(compound_emb))

    print(f"GNN embedding differentiation test passed: distance={distance:.4f}")


if __name__ == "__main__":
    test_gnn_represents_compound_patterns()
    test_gnn_produces_different_embeddings_for_different_graphs()
    print("All GNN-specific tests passed!")
