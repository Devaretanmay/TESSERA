import pytest
from tessera.topology.models import (
    TopologyNode,
    TopologyEdge,
    TopologyGraph,
    NodeType,
    TrustBoundary,
    FlowType,
    TrustLevel,
)


def test_topology_node_creation():
    node = TopologyNode(
        id="test_model",
        type=NodeType.MODEL,
        provider="openai",
        model="gpt-4o",
        trust_boundary=TrustBoundary.USER_CONTROLLED,
    )
    assert node.id == "test_model"
    assert node.type == NodeType.MODEL


def test_topology_graph_add_node():
    graph = TopologyGraph(system="test_system")
    node = TopologyNode(
        id="model",
        type=NodeType.MODEL,
        trust_boundary=TrustBoundary.USER_CONTROLLED,
    )
    graph.add_node(node)
    assert "model" in graph.nodes


def test_topology_graph_add_edge():
    graph = TopologyGraph(system="test_system")
    graph.add_node(
        TopologyNode(id="a", type=NodeType.MODEL, trust_boundary=TrustBoundary.USER_CONTROLLED)
    )
    graph.add_node(
        TopologyNode(
            id="b", type=NodeType.RAG_CORPUS, trust_boundary=TrustBoundary.PARTIALLY_TRUSTED
        )
    )

    edge = TopologyEdge(
        from_node="a", to_node="b", flow=FlowType.RETRIEVAL, trust_level=TrustLevel.UNTRUSTED
    )
    graph.add_edge(edge)

    assert len(graph.edges) == 1
    assert len(graph.get_edges_from("a")) == 1


def test_topology_attack_surface():
    graph = TopologyGraph(system="test_system")
    graph.add_node(
        TopologyNode(id="model", type=NodeType.MODEL, trust_boundary=TrustBoundary.USER_CONTROLLED)
    )
    graph.add_node(
        TopologyNode(
            id="rag", type=NodeType.RAG_CORPUS, trust_boundary=TrustBoundary.PARTIALLY_TRUSTED
        )
    )

    edge = TopologyEdge(
        from_node="model", to_node="rag", flow=FlowType.RETRIEVAL, trust_level=TrustLevel.UNTRUSTED
    )
    graph.add_edge(edge)

    surface = graph.attack_surface()
    assert len(surface) == 1
    assert surface[0]["edge"] == "model->rag"
