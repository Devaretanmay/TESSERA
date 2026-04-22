"""
CFPE Detection patterns.
"""

from dataclasses import dataclass
from enum import Enum
from tessera.core.topology.models import Graph, Edge, TrustBoundary, DataFlow


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    COMPOUND_CHAIN = "compound_chain"
    ATOMIC_INJECTION = "atomic_injection"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    TRUST_BOUNDARY_BYPASS = "trust_boundary_bypass"


@dataclass
class Finding:
    id: str
    severity: Severity
    category: Category
    description: str
    edges: list[str]
    indicators: list[str]
    remediation: dict = None

    def __post_init__(self):
        if self.remediation is None:
            self.remediation = {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "edges": self.edges,
            "indicators": self.indicators,
            "remediation": self.remediation,
        }


class DetectionRule:
    id: str
    name: str
    applies_to: set[str]

    def detect(self, graph: Graph) -> list[Finding]:
        raise NotImplementedError


class CFPE0001Rule(DetectionRule):
    id = "CFPE-0001"
    name = "RAG to Tool"
    applies_to = {"llm", "model", "rag_corpus", "tool"}
    remediation = {
        "summary": "Validate RAG outputs before tool execution",
        "how_to_fix": (
            "1. Validate RAG outputs before tool execution\n"
            "2. Implement least-privilege for tool access\n"
            "3. Add output sanitization between RAG and tools\n"
            "4. Use separate privilege boundaries"
        ),
        "references": ["OWASP LLM02", "CWE-20"],
    }

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        has_rag = any(n.type in ("rag_corpus", "model") for n in graph.nodes.values())
        has_tool = any(n.type == "tool" for n in graph.nodes.values())

        if has_rag and has_tool:
            edge_ids = []
            for edge in graph.edges:
                if edge.data_flow == DataFlow.TOOL_CALL:
                    edge_ids.append(f"{edge.from_node}->{edge.to_node}")

            if edge_ids:
                findings.append(
                    Finding(
                        id=self.id,
                        severity=Severity.HIGH,
                        category=Category.COMPOUND_CHAIN,
                        description="RAG to Tool execution chain detected",
                        edges=edge_ids,
                        indicators=["rag_tool_chain"],
                        remediation=self.remediation,
                    )
                )

        return findings


class CFPE0002Rule(DetectionRule):
    id = "CFPE-0002"
    name = "Memory Poisoning"
    applies_to = {"llm", "model", "memory_store"}
    remediation = {
        "summary": "Use read-only memory for RAG context",
        "how_to_fix": (
            "1. Use read-only memory stores for RAG context\n"
            "2. Implement memory integrity verification\n"
            "3. Separate user context from system memory\n"
            "4. Add memory signing/verification"
        ),
        "references": ["OWASP LLM03", "CWE-20"],
    }

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []
        node_types = {n.type for n in graph.nodes.values()}

        if "memory_store" in node_types or "memory" in node_types:
            for edge in graph.edges:
                if edge.data_flow == DataFlow.READ_WRITE:
                    findings.append(
                        Finding(
                            id=self.id,
                            severity=Severity.CRITICAL,
                            category=Category.COMPOUND_CHAIN,
                            description="Memory poisoning risk - write to persistent memory",
                            edges=[f"{edge.from_node}->{edge.to_node}"],
                            indicators=["memory_persist"],
                            remediation=self.remediation,
                        )
                    )

        return findings


class CFPE0004Rule(DetectionRule):
    id = "CFPE-0004"
    name = "Agent Context Propagation"
    applies_to = {"llm", "model", "tool"}
    remediation = {
        "summary": "Implement trust boundary validation and data sanitization",
        "how_to_fix": (
            "1. Define clear trust boundaries\n"
            "2. Validate data at each boundary\n"
            "3. Implement sanitization functions\n"
            "4. Add firewall rules for cross-boundary flows"
        ),
        "references": ["OWASP LLM04", "CWE-20"],
    }

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        for edge in graph.edges:
            from_node = graph.nodes.get(edge.from_node)
            to_node = graph.nodes.get(edge.to_node)

            if (
                from_node
                and to_node
                and from_node.trust_boundary != to_node.trust_boundary
                and edge.trust_boundary == TrustBoundary.EXTERNAL
            ):
                findings.append(
                    Finding(
                        id=self.id,
                        severity=Severity.HIGH,
                        category=Category.TRUST_BOUNDARY_BYPASS,
                        description=f"Untrusted data flows to {edge.to_node}",
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["trust_crossing"],
                        remediation=self.remediation,
                    )
                )

        return findings


class CFPE0003Rule(DetectionRule):
    """CFPE-0003: External to Database

    Detects when untrusted/external data can directly access databases
    without proper validation, enabling potential data exfiltration.
    """

    id = "CFPE-0003"
    name = "External to Database"
    applies_to = {"external", "user", "database", "user_controlled"}
    remediation = {
        "summary": "Add validation layer between external inputs and database",
        "how_to_fix": (
            "1. Add input validation layer before database access\n"
            "2. Use parameterized queries\n"
            "3. Implement database firewall rules\n"
            "4. Add rate limiting on database endpoints\n"
            "5. Use connection pooling with access controls"
        ),
        "references": ["OWASP LLM04", "CWE-20", "CWE-89"],
    }

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        for edge in graph.edges:
            from_node = graph.nodes.get(edge.from_node)
            to_node = graph.nodes.get(edge.to_node)

            if not from_node or not to_node:
                continue

            is_untrusted = from_node.trust_boundary in (
                TrustBoundary.EXTERNAL,
                TrustBoundary.USER_CONTROLLED,
            )
            is_database = to_node.type == "database"

            if is_untrusted and is_database:
                findings.append(
                    Finding(
                        id=self.id,
                        severity=Severity.HIGH,
                        category=Category.TRUST_BOUNDARY_BYPASS,
                        description=f"Untrusted source '{edge.from_node}' directly accesses database '{edge.to_node}'",
                        edges=[f"{edge.from_node}->{edge.to_node}"],
                        indicators=["untrusted_database_access"],
                        remediation=self.remediation,
                    )
                )

        return findings


class CFPE0005Rule(DetectionRule):
    """CFPE-0005: Multi-hop Attack Chain

    Detects complex attack chains that span 3 or more edges in the topology.
    These represent sophisticated attacks that chain multiple vulnerabilities.
    """

    id = "CFPE-0005"
    name = "Multi-hop Attack Chain"
    applies_to = {"llm", "tool", "rag_corpus", "memory_store", "database"}
    remediation = {
        "summary": "Break long attack chains with validation points",
        "how_to_fix": (
            "1. Break long chains with validation points\n"
            "2. Implement multiple security layers\n"
            "3. Monitor chain interactions\n"
            "4. Add circuit breakers between hops\n"
            "5. Log and alert on multi-hop flows"
        ),
        "references": ["OWASP LLM02", "MITRE ATT&CK"],
    }

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        # Build adjacency list
        adj = {node_id: [] for node_id in graph.nodes}
        for edge in graph.edges:
            adj[edge.from_node].append(edge.to_node)

        # Find all paths of length 3+ using BFS
        def find_long_paths(start: str, max_depth: int = 3) -> list[list[str]]:
            paths = []
            stack = [(start, [start], 0)]

            while stack:
                node, path, depth = stack.pop()

                if depth >= max_depth:
                    paths.append(path)
                    continue

                for neighbor in adj.get(node, []):
                    if neighbor not in path:  # Avoid cycles
                        stack.append((neighbor, path + [neighbor], depth + 1))

            return paths

        # Check for dangerous multi-hop paths
        dangerous_types = {"tool", "database", "external_service", "memory_store"}

        for node_id in graph.nodes:
            long_paths = find_long_paths(node_id)

            for path in long_paths:
                # Check if path ends in dangerous component
                end_node = graph.nodes.get(path[-1])
                if end_node and end_node.type in dangerous_types:
                    # Check if path starts from untrusted
                    start_node = graph.nodes.get(path[0])
                    if start_node and start_node.trust_boundary in (
                        TrustBoundary.EXTERNAL,
                        TrustBoundary.USER_CONTROLLED,
                    ):
                        edge_path = " -> ".join(path)
                        findings.append(
                            Finding(
                                id=self.id,
                                severity=Severity.HIGH,
                                category=Category.COMPOUND_CHAIN,
                                description=f"Multi-hop attack chain detected ({len(path)} hops): {edge_path}",
                                edges=[f"{path[i]}->{path[i + 1]}" for i in range(len(path) - 1)],
                                indicators=["multi_hop_chain", f"hops_{len(path)}"],
                                remediation=self.remediation,
                            )
                        )

        return findings


class CFPE0006Rule(DetectionRule):
    """CFPE-0006: Tool to Tool Chaining

    Detects when one tool can call another, potentially escalating
    privileges or creating unexpected behavior chains.
    """

    id = "CFPE-0006"
    name = "Tool to Tool Chaining"
    applies_to = {"tool"}
    remediation = {
        "summary": "Limit tool-to-tool communication and implement isolation",
        "how_to_fix": (
            "1. Limit tool-to-tool communication\n"
            "2. Implement tool permission model\n"
            "3. Audit tool interaction logs\n"
            "4. Use sandboxing for tool execution\n"
            "5. Add approval workflow for tool chains"
        ),
        "references": ["OWASP LLM05", "CWE-749"],
    }

    def detect(self, graph: Graph) -> list[Finding]:
        findings = []

        # Find all tools
        tools = {node_id: node for node_id, node in graph.nodes.items() if node.type == "tool"}

        if len(tools) < 2:
            return findings

        # Check for tool-to-tool edges
        tool_to_tool_edges = []
        for edge in graph.edges:
            from_is_tool = edge.from_node in tools
            to_is_tool = edge.to_node in tools

            if from_is_tool and to_is_tool:
                tool_to_tool_edges.append(f"{edge.from_node}->{edge.to_node}")

        if tool_to_tool_edges:
            findings.append(
                Finding(
                    id=self.id,
                    severity=Severity.MEDIUM,
                    category=Category.COMPOUND_CHAIN,
                    description=f"Tool chaining detected: {', '.join(tool_to_tool_edges)}",
                    edges=tool_to_tool_edges,
                    indicators=["tool_chain"],
                    remediation=self.remediation,
                )
            )

        return findings


RULES = [
    CFPE0001Rule(),
    CFPE0002Rule(),
    CFPE0003Rule(),
    CFPE0004Rule(),
    CFPE0005Rule(),
    CFPE0006Rule(),
]


def detect(graph: Graph) -> list[Finding]:
    """Detect vulnerabilities in a topology graph.

    Args:
        graph: Graph to scan

    Returns:
        List of Finding objects
    """
    results = []
    for rule in RULES:
        results.extend(rule.detect(graph))
    return results


def detect_as_dicts(graph: Graph) -> list[dict]:
    """Detect vulnerabilities and return as dictionaries.

    Args:
        graph: Graph to scan

    Returns:
        List of finding dictionaries suitable for formatters
    """
    findings = detect(graph)
    return [f.to_dict() for f in findings]
