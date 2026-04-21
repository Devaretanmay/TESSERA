"""
RDT Configuration for TESSERA security scanner.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class RDTConfig:
    """Configuration for Recurrent-Depth Transformer model."""

    # Model dimensions
    dim: int = 256
    hidden_dim: int = 512

    # Attention
    n_heads: int = 8
    head_dim: int = 32

    # Recurrent block
    max_loop_iters: int = 8
    prelude_layers: int = 2
    coda_layers: int = 2

    # MoE (Mixture of Experts)
    n_experts: int = 8
    n_shared_experts: int = 2
    n_experts_per_tok: int = 2
    expert_dim: int = 64

    # Stability (Parcae)
    spectral_radius_target: float = 0.95
    stability_coef: float = 0.1

    # ACT (Adaptive Computation Time)
    halting_bonus: float = 0.1
    target_halting: float = 0.5

    # Training
    dropout: float = 0.1
    lr: float = 1e-4
    weight_decay: float = 0.01
    grad_clip: float = 1.0

    # Data
    vocab_size: int = 20
    num_trust_levels: int = 6
    num_data_flows: int = 6
    num_vuln_classes: int = 4  # benign, suspicious, high, critical

    # Inference
    default_loops: int = 4
    min_loops: int = 1


# Pre-configured scales
def rdt_small() -> RDTConfig:
    """Small model - ~10M params."""
    return RDTConfig(
        dim=128,
        hidden_dim=256,
        n_heads=4,
        max_loop_iters=4,
        prelude_layers=1,
        coda_layers=1,
        n_experts=4,
    )


def rdt_medium() -> RDTConfig:
    """Medium model - ~50M params."""
    return RDTConfig(
        dim=256,
        hidden_dim=512,
        n_heads=8,
        max_loop_iters=8,
        prelude_layers=2,
        coda_layers=2,
        n_experts=8,
    )


def rdt_large() -> RDTConfig:
    """Large model - ~100M params."""
    return RDTConfig(
        dim=512,
        hidden_dim=1024,
        n_heads=16,
        max_loop_iters=12,
        prelude_layers=3,
        coda_layers=3,
        n_experts=16,
        n_shared_experts=4,
    )
