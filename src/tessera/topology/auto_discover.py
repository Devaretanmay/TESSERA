"""Auto-discovery from external sources."""

import yaml
from pathlib import Path


class OpenAPITopologyBuilder:
    """Build topology from OpenAPI spec."""

    def __init__(self, spec_path: str | Path):
        self.spec_path = Path(spec_path)
        self.spec = None

    def load(self) -> dict:
        """Load OpenAPI spec."""
        with open(self.spec_path) as f:
            self.spec = yaml.safe_load(f)
        return self.spec

    def to_topology(self) -> dict:
        """Convert OpenAPI spec to TESSERA topology."""
        if not self.spec:
            self.load()

        spec = self.spec
        info = spec.get("info", {})

        nodes = []
        edges = []

        servers = spec.get("servers", [{"url": "https://api.example.com"}])
        base_url = servers[0].get("url", "https://api.example.com")

        nodes.append(
            {
                "id": "api_gateway",
                "type": "api",
                "trust_boundary": "user_controlled",
            }
        )

        if "openai" in base_url.lower() or "gpt" in base_url.lower():
            nodes.append(
                {
                    "id": "llm",
                    "type": "model",
                    "provider": "openai",
                    "model": "gpt-4",
                    "trust_boundary": "trusted",
                }
            )
            edges.append(
                {
                    "from": "api_gateway",
                    "to": "llm",
                    "flow": "api",
                    "trust_level": "untrusted",
                }
            )

        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if isinstance(methods, dict):
                for method, details in methods.items():
                    if method.lower() in ["get", "post", "put", "delete"]:
                        op_id = details.get("operationId", path.strip("/").replace("/", "_"))
                        if "search" in path or "query" in path:
                            nodes.append(
                                {
                                    "id": "rag_index",
                                    "type": "rag_corpus",
                                    "trust_boundary": "partially_trusted",
                                }
                            )
                            edges.append(
                                {
                                    "from": "llm",
                                    "to": "rag_index",
                                    "flow": "retrieval",
                                    "trust_level": "untrusted",
                                }
                            )
                        elif "db" in path or "data" in path:
                            nodes.append(
                                {
                                    "id": "database",
                                    "type": "memory",
                                    "trust_boundary": "internal",
                                }
                            )
                            edges.append(
                                {
                                    "from": "llm",
                                    "to": "database",
                                    "flow": "read_write",
                                    "trust_level": "internal",
                                }
                            )
                        else:
                            nodes.append(
                                {
                                    "id": op_id,
                                    "type": "tool",
                                    "trust_boundary": "internal",
                                }
                            )
                            edges.append(
                                {
                                    "from": "llm",
                                    "to": op_id,
                                    "flow": "tool_call",
                                    "trust_level": "internal",
                                }
                            )

        nodes.append(
            {
                "id": "response",
                "type": "output",
                "trust_boundary": "trusted",
            }
        )
        edges.append(
            {
                "from": "llm",
                "to": "response",
                "flow": "api",
                "trust_level": "trusted",
            }
        )

        return {
            "system": info.get("title", "auto_discovered").replace(" ", "_"),
            "version": info.get("version", "1.0"),
            "nodes": nodes,
            "edges": edges,
        }


class LangGraphTopologyBuilder:
    """Build topology from LangGraph definition."""

    def __init__(self, graph_def: dict):
        self.graph = graph_def

    def to_topology(self) -> dict:
        """Convert LangGraph to TESSERA topology."""
        nodes = []
        edges = []

        graph_state = self.graph.get("state", {})
        state_class = graph_state.get("class", "dict")

        nodes.append(
            {
                "id": "state",
                "type": "memory",
                "trust_boundary": "partially_trusted",
            }
        )

        nodes_by_type = {}

        for node_id, node_def in self.graph.get("nodes", {}).items():
            node_type = node_def.get("type", "unknown")
            nodes_by_type[node_id] = node_type

            if "llm" in node_type.lower() or "chat" in node_type.lower():
                nodes.append(
                    {
                        "id": node_id,
                        "type": "model",
                        "trust_boundary": "trusted",
                    }
                )
            elif "tool" in node_type.lower():
                nodes.append(
                    {
                        "id": node_id,
                        "type": "tool",
                        "trust_boundary": "internal",
                    }
                )
            elif "retriever" in node_type.lower() or "search" in node_type.lower():
                nodes.append(
                    {
                        "id": node_id,
                        "type": "rag_corpus",
                        "trust_boundary": "partially_trusted",
                    }
                )
            else:
                nodes.append(
                    {
                        "id": node_id,
                        "type": "model",
                        "trust_boundary": "trusted",
                    }
                )

        for edge in self.graph.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            if source and target:
                source_type = nodes_by_type.get(source, "unknown")
                target_type = nodes_by_type.get(target, "unknown")

                if "tool" in target_type:
                    flow = "tool_call"
                elif "rag" in target_type:
                    flow = "retrieval"
                else:
                    flow = "api"

                edges.append(
                    {
                        "from": source,
                        "to": target,
                        "flow": flow,
                        "trust_level": "untrusted",
                    }
                )

        nodes.append(
            {
                "id": "user_input",
                "type": "user_input",
                "trust_boundary": "user_controlled",
            }
        )

        start = self.graph.get("_entry", "agent")
        edges.append(
            {
                "from": "user_input",
                "to": start,
                "flow": "api",
                "trust_level": "user_controlled",
            }
        )

        return {
            "system": "langgraph_auto",
            "version": "1.0",
            "nodes": nodes,
            "edges": edges,
        }


def auto_discover(source: str) -> dict | None:
    """Auto-discover topology from various sources."""
    path = Path(source)

    if not path.exists():
        return None

    if source.endswith(".yaml") or source.endswith(".yml"):
        with open(path) as f:
            data = yaml.safe_load(f)

        if "openapi" in str(data.get("", "")):
            builder = OpenAPITopologyBuilder(source)
            return builder.to_topology()

        if "nodes" in data and "edges" in data:
            builder = LangGraphTopologyBuilder(data)
            return builder.to_topology()

    return None
