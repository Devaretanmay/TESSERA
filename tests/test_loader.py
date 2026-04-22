from __future__ import annotations

import pytest

from tessera.core.topology.loader import Loader, ValidationError


def test_loader_load_and_load_from_string_are_consistent(tmp_path):
    content = """
system: test-agent
version: "1.0"
nodes:
  - id: user
    type: user
    trust_boundary: external
  - id: llm
    type: llm
    trust_boundary: internal
edges:
  - from: user
    to: llm
    flow: api
    trust_boundary: external
"""
    topology_file = tmp_path / "topology.yaml"
    topology_file.write_text(content, encoding="utf-8")

    loader = Loader()
    graph_from_file = loader.load(topology_file)
    graph_from_string = loader.load_from_string(content)

    assert graph_from_file.system == graph_from_string.system
    assert graph_from_file.version == graph_from_string.version
    assert graph_from_file.nodes.keys() == graph_from_string.nodes.keys()
    assert len(graph_from_file.edges) == len(graph_from_string.edges)


def test_loader_rejects_non_mapping_yaml_root():
    loader = Loader()

    with pytest.raises(ValidationError, match="invalid YAML root"):
        loader.load_from_string("- not-a-mapping")


def test_loader_missing_nodes_or_edges_mentions_source():
    loader = Loader()

    with pytest.raises(ValidationError, match="<string>: missing nodes or edges"):
        loader.load_from_string("system: bad")
