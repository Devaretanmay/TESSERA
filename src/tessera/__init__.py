# TESSERA Core Package
__version__ = "0.1.0"

from tessera.core.topology.models import Graph, Node, Edge, TrustBoundary, DataFlow
from tessera.core.findings.models import Finding, FindingSeverity, FailureType
from tessera.core.detection.patterns import detect

__all__ = [
    "Graph",
    "Node",
    "Edge",
    "TrustBoundary",
    "DataFlow",
    "Finding",
    "FindingSeverity",
    "FailureType",
    "detect",
]
