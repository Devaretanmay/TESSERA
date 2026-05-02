"""Risk scoring engine for TESSERA.

Risk = f(chain_length, boundary_crossings, node_types, exploitability, data_sensitivity)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary


class RiskLevel(str, Enum):
    CRITICAL = "critical"  # 8-10
    HIGH = "high"          # 6-7.9
    MEDIUM = "medium"      # 4-5.9
    LOW = "low"            # 2-3.9
    INFO = "info"          # 0-1.9


DEFAULT_NODE_RISK_WEIGHTS: dict[str, float] = {
    "external_service": 2.5,
    "tool": 2.0,
    "database": 2.5,
    "memory_store": 1.5,
    "rag_corpus": 1.8,
    "llm": 1.2,
    "api": 1.0,
    "user": 0.5,
}

DEFAULT_DATA_SENSITIVITY: dict[str, float] = {
    "pii": 2.0,
    "credentials": 2.5,
    "financial": 2.5,
    "health": 2.5,
    "internal": 1.5,
    "public": 0.5,
}

BOUNDARY_RISK_PAIRS = {
    (TrustBoundary.EXTERNAL, TrustBoundary.INTERNAL): 1.5,
    (TrustBoundary.EXTERNAL, TrustBoundary.PRIVILEGED): 2.0,
    (TrustBoundary.USER_CONTROLLED, TrustBoundary.INTERNAL): 1.3,
    (TrustBoundary.USER_CONTROLLED, TrustBoundary.PRIVILEGED): 1.8,
    (TrustBoundary.PARTIALLY_TRUSTED, TrustBoundary.PRIVILEGED): 1.2,
}


@dataclass
class RiskConfig:
    """Configuration for RiskScorer."""

    node_weights: dict[str, float] = field(default_factory=lambda: DEFAULT_NODE_RISK_WEIGHTS.copy())
    data_sensitivity: dict[str, float] = field(default_factory=lambda: DEFAULT_DATA_SENSITIVITY.copy())
    boundary_pairs: dict[tuple[TrustBoundary, TrustBoundary], float] = field(default_factory=lambda: {
        (TrustBoundary.EXTERNAL, TrustBoundary.INTERNAL): 1.5,
        (TrustBoundary.EXTERNAL, TrustBoundary.PRIVILEGED): 2.0,
        (TrustBoundary.USER_CONTROLLED, TrustBoundary.INTERNAL): 1.3,
        (TrustBoundary.USER_CONTROLLED, TrustBoundary.PRIVILEGED): 1.8,
        (TrustBoundary.PARTIALLY_TRUSTED, TrustBoundary.PRIVILEGED): 1.2,
    })
    chain_length_weight: float = 0.8
    boundary_crossing_weight: float = 1.2
    max_chain_length: int = 6
    high_value_weight: float = 2.0


@dataclass
class AttackPath:
    """Represents a potential attack path through the topology."""
    nodes: list[str]
    edges: list[str]
    chain_length: int
    boundary_crossings: int
    risk_factors: list[str]
    score: float
    level: RiskLevel

    def to_dict(self) -> dict:
        return {
            "path": " -> ".join(self.nodes),
            "chain_length": self.chain_length,
            "boundary_crossings": self.boundary_crossings,
            "risk_factors": self.risk_factors,
            "score": round(self.score, 2),
            "level": self.level.value,
        }


@dataclass
class RiskAssessment:
    """Complete risk assessment for a topology."""
    topology_name: str
    overall_score: float
    level: RiskLevel
    attack_paths: list[AttackPath]
    critical_chains: int
    boundary_violations: int
    recommendations: list[str]

    def to_dict(self) -> dict:
        return {
            "topology": self.topology_name,
            "risk_score": round(self.overall_score, 2),
            "risk_level": self.level.value,
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "critical_chains": self.critical_chains,
            "boundary_violations": self.boundary_violations,
            "recommendations": self.recommendations,
        }

    def to_explanation(self) -> str:
        """Human-readable risk explanation."""
        lines = [
            f"Risk Score: {self.overall_score:.1f}/10 ({self.level.value.upper()})",
            f"Critical Chains: {self.critical_chains}",
            f"Boundary Violations: {self.boundary_violations}",
            "",
            "Attack Paths:",
]
        for i, path in enumerate(self.attack_paths[:5], 1):
            path_str = " -> ".join(path.nodes)
            lines.append(f" {i}. {path_str}")
            lines.append(f"     Score: {path.score:.1f} | Length: {path.chain_length} | Boundaries: {path.boundary_crossings}")
        return "\n".join(lines)


class RiskScorer:
    """Calculate risk scores for topologies and attack paths."""

    def __init__(self, config: RiskConfig | None = None):
        self._config = config or RiskConfig()

    @property
    def config(self) -> RiskConfig:
        """Get current config."""
        return self._config

    def score_node(self, node: Node) -> float:
        """Score individual node risk."""
        base = self._config.node_weights.get(node.type, 1.0)

        boundary_mult = {
            TrustBoundary.EXTERNAL: 1.5,
            TrustBoundary.USER_CONTROLLED: 1.3,
            TrustBoundary.PARTIALLY_TRUSTED: 1.1,
            TrustBoundary.INTERNAL: 1.0,
            TrustBoundary.PRIVILEGED: 0.8,
            TrustBoundary.PUBLIC: 0.5,
        }.get(node.trust_boundary, 1.0)

        return base * boundary_mult

    def score_boundary_pair(self, from_boundary: TrustBoundary, to_boundary: TrustBoundary) -> float:
        """Score risk of boundary crossing."""
        return self._config.boundary_pairs.get((from_boundary, to_boundary), 1.0)

    def score_path(
        self,
        nodes: list[Node],
        edges: list[Edge],
        chain_length: int,
        boundary_crossings: int,
    ) -> float:
        """Score entire attack path.

        Formula:
        score = (chain_length * chain_length_weight)
              + (boundary_crossings * boundary_crossing_weight)
              + sum(node_risks)
              + chain_length_penalty
        """
        if not nodes:
            return 0.0

        high_value_types = {"database", "external_service", "tool"}
        high_value_nodes = [n for n in nodes if n.type in high_value_types]
        node_risk = len(high_value_nodes) * self._config.high_value_weight

        edge_risk = boundary_crossings * self._config.boundary_crossing_weight

        chain_penalty = 0.0
        if chain_length > 4:
            chain_penalty = (chain_length - 4) * self._config.chain_length_weight

        total = node_risk + edge_risk + chain_penalty

        return min(total, 10.0)

    def risk_level(self, score: float) -> RiskLevel:
        """Map score to risk level."""
        if score >= 8:
            return RiskLevel.CRITICAL
        if score >= 6:
            return RiskLevel.HIGH
        if score >= 4:
            return RiskLevel.MEDIUM
        if score >= 2:
            return RiskLevel.LOW
        return RiskLevel.INFO


def assess_risk(graph: Graph, topology_name: str = "unknown") -> RiskAssessment:
    """Run full risk assessment on a topology."""
    from tessera.core.detection.rules.helpers import build_adjacency, get_node

    scorer = RiskScorer()
    adj = build_adjacency(graph)
    
    # Map (from, to) -> edge for O(1) lookup
    edge_map = {(e.from_node, e.to_node): e for e in graph.edges}

    # Find all paths up to max_length
    all_paths: list[AttackPath] = []
    boundary_violations = 0
    critical_chains = 0

    for start_id in graph.nodes:
        paths = _find_all_paths(adj, graph, start_id, max_depth=scorer.config.max_chain_length)
        for path_node_ids in paths:
            if len(path_node_ids) < 2:
                continue

            # Get edge objects
            path_edges = []
            for i in range(len(path_node_ids) - 1):
                edge = edge_map.get((path_node_ids[i], path_node_ids[i+1]))
                if edge:
                    path_edges.append(edge)
                    if edge.trust_boundary == TrustBoundary.EXTERNAL:
                        boundary_violations += 1

            # Get node objects
            path_nodes = [get_node(graph, nid) for nid in path_node_ids]
            path_nodes = [n for n in path_nodes if n is not None]

            # Count boundary crossings
            crossings = 0
            for i in range(len(path_nodes) - 1):
                if path_nodes[i].trust_boundary != path_nodes[i + 1].trust_boundary:
                    crossings += 1

            # Score
            score = scorer.score_path(path_nodes, path_edges, len(path_node_ids), crossings)
            level = scorer.risk_level(score)

            if level == RiskLevel.CRITICAL:
                critical_chains += 1

            # Risk factors
            factors = []
            if len(path_node_ids) >= 4:
                factors.append("long_chain")
            if crossings > 0:
                factors.append("boundary_crossing")
            if any(n.type in ("database", "external_service") for n in path_nodes):
                factors.append("high_value_target")
            if any(n.type == "tool" for n in path_nodes):
                factors.append("tool_usage")

            all_paths.append(AttackPath(
                nodes=path_node_ids,
                edges=[f"{path_node_ids[i]}->{path_node_ids[i+1]}" for i in range(len(path_node_ids)-1)],
                chain_length=len(path_node_ids),
                boundary_crossings=crossings,
                risk_factors=factors,
                score=score,
                level=level,
            ))

    # Sort by score descending
    all_paths.sort(key=lambda p: p.score, reverse=True)

    # Overall score = weighted average of top paths
    if all_paths:
        top_paths = all_paths[:10]
        overall = sum(p.score for p in top_paths) / len(top_paths)
        overall += len([p for p in all_paths if p.level == RiskLevel.CRITICAL]) * 0.5
        overall = min(overall, 10.0)
    else:
        overall = 0.0

    # Recommendations
    recs = []
    if critical_chains > 0:
        recs.append(f"Reduce {critical_chains} critical chain(s)")
    if boundary_violations > 0:
        recs.append(f"Add validation at {boundary_violations} trust boundary crossing(s)")
    if any(p.chain_length >= 4 for p in all_paths):
        recs.append("Break long attack chains with validation points")
    if not recs:
        recs.append("No critical issues detected")

    return RiskAssessment(
        topology_name=topology_name,
        overall_score=overall,
        level=scorer.risk_level(overall),
        attack_paths=all_paths[:20],  # Top 20
        critical_chains=critical_chains,
        boundary_violations=boundary_violations,
        recommendations=recs,
    )


def _find_all_paths(
    adj: dict[str, list[str]],
    graph: Graph,
    start: str,
    max_depth: int = 5,
    min_length: int = 2,
) -> list[list[str]]:
    """Find all paths from start up to max_depth (min_length+)."""
    paths: list[list[str]] = []

    def dfs(node: str, path: list[str], depth: int):
        # Store path if long enough (regardless of depth)
        if len(path) >= min_length:
            paths.append(path[:])

        if depth >= max_depth:
            return

        for neighbor in adj.get(node, []):
            if neighbor not in path:  # No cycles
                path.append(neighbor)
                dfs(neighbor, path, depth + 1)
                path.pop()

    dfs(start, [start], 0)
    return paths