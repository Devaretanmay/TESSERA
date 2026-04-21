"""
TESSERA RDT - Recurrent-Depth Transformer for Compound Attack Detection.
"""

from tessera.rdt.config import RDTConfig
from tessera.rdt.gnn_scanner import GNNScanner

__version__ = "1.0.0"

__all__ = [
    "RDTConfig",
    "GNNScanner",
]
