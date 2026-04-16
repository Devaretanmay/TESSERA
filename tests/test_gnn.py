import pytest
import numpy as np
from tessera.classifier.gnn.data import (
    TopologyGraph,
    GraphNode,
    GraphEdge,
    NodeType,
    TrustLevel,
)
from tessera.classifier.gnn.model import GraphSAGEModel, GNNConfig


def test_gnn_message_passing_propagates_through_graph():
    """GNN forward pass should propagate information through actual graph structure.
    
    If node A connects to node B, changing B's features should change A's embedding.
    This is the core GraphSAGE invariant: message passing means neighbor features flow through.
    """
    config = GNNConfig(input_dim=16, hidden_dim=32, output_dim=8, num_layers=2, dropout=0.0)
    
    # Create a simple chain: A → B → C
    graph = TopologyGraph()
    graph.add_node(GraphNode(id="A", node_type=NodeType.LLM))
    graph.add_node(GraphNode(id="B", node_type=NodeType.RAG))
    graph.add_node(GraphNode(id="C", node_type=NodeType.TOOL))
    graph.add_edge(GraphEdge(from_node="A", to_node="B", edge_type="prompt"))
    graph.add_edge(GraphEdge(from_node="B", to_node="C", edge_type="tool_call"))

    features = graph.to_feature_matrix()
    adj = np.zeros((3, 3))
    adj[0, 1] = 1  # A → B
    adj[1, 2] = 1  # B → C

    # Run forward pass with original features
    model1 = GraphSAGEModel(config)
    embeddings1 = model1.forward(features, adj)

    # Change B's features deterministically
    features_modified = features.copy()
    features_modified[1] = features[1] * 10  # Scale B's features significantly

    # Run forward pass with modified B
    model2 = GraphSAGEModel(config)
    # Use same weights as model1 for fair comparison
    model2._weights = model1._weights
    model2._initialized = True
    embeddings2 = model2.forward(features_modified, adj)

    # CRITICAL: A's embedding should change because B (A's neighbor) changed
    # This is the GraphSAGE message passing invariant
    assert not np.allclose(embeddings1[0], embeddings2[0]), \
        "A's embedding should change when B's features change (message passing)"
    
    # B's embedding should also change (it has different input features)
    assert not np.allclose(embeddings1[1], embeddings2[1]), \
        "B's embedding should change when its own features change"
    
    # C's embedding should NOT change (C has no incoming edges, B's change shouldn't affect it)
    assert np.allclose(embeddings1[2], embeddings2[2]), \
        "C's embedding should NOT change when B changes (no path from B to C in adjacency)"


def test_gnn_distinguishes_chain_exploitation_from_safe():
    """GNN should produce different embeddings for chain exploitation vs safe graph structures.
    
    A RAG→tool chain with untrusted nodes should embed differently than isolated trusted nodes.
    This tests whether the GNN can actually learn to detect compound failure patterns.
    """
    config = GNNConfig(input_dim=16, hidden_dim=32, output_dim=8, num_layers=2, dropout=0.0)
    
    # Safe graph: isolated trusted nodes, no edges
    safe_graph = TopologyGraph()
    safe_graph.add_node(GraphNode(id="llm_1", node_type=NodeType.LLM, trust=TrustLevel.TRUSTED))
    safe_graph.add_node(GraphNode(id="tool_1", node_type=NodeType.TOOL, trust=TrustLevel.TRUSTED))
    # No edges → isolated
    
    # Chain exploitation graph: LLM→RAG→tool with untrusted nodes
    attack_graph = TopologyGraph()
    attack_graph.add_node(GraphNode(id="llm_1", node_type=NodeType.LLM, trust=TrustLevel.UNTRUSTED))
    attack_graph.add_node(GraphNode(id="rag_1", node_type=NodeType.RAG, trust=TrustLevel.UNTRUSTED))
    attack_graph.add_node(GraphNode(id="tool_1", node_type=NodeType.TOOL, trust=TrustLevel.UNTRUSTED))
    attack_graph.add_edge(GraphEdge(from_node="llm_1", to_node="rag_1", edge_type="prompt"))
    attack_graph.add_edge(GraphEdge(from_node="rag_1", to_node="tool_1", edge_type="tool_call"))
    
    safe_features = safe_graph.to_feature_matrix()
    safe_adj = np.zeros((2, 2))  # No edges
    
    attack_features = attack_graph.to_feature_matrix()
    attack_adj = np.zeros((3, 3))
    attack_adj[0, 1] = 1  # llm → rag
    attack_adj[1, 2] = 1  # rag → tool
    
    model = GraphSAGEModel(config)
    safe_embeddings = model.forward(safe_features, safe_adj)
    attack_embeddings = model.forward(attack_features, attack_adj)
    
    # Graph embeddings (mean of node embeddings) should be significantly different
    safe_graph_emb = safe_embeddings.mean(axis=0)
    attack_graph_emb = attack_embeddings.mean(axis=0)
    
    # Cosine similarity should be low (different patterns)
    cosine_sim = np.dot(safe_graph_emb, attack_graph_emb) / (
        np.linalg.norm(safe_graph_emb) * np.linalg.norm(attack_graph_emb) + 1e-8
    )
    
    # Should be distinguishable (cosine sim < 0.9 means different enough)
    assert cosine_sim < 0.9, \
        f"Safe and attack graphs should produce distinguishable embeddings (sim={cosine_sim:.3f})"
