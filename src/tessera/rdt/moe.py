"""
Sparse Mixture of Experts implementation for TESSERA RDT.
Based on DeepSeek MoE design.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple


class SparseMoE(nn.Module):
    """
    Sparse Mixture of Experts layer.

    Features:
    - Fine-grained expert segmentation
    - Shared experts (always active)
    - Load balancing via auxiliary loss
    - Gating with top-k selection
    """

    def __init__(
        self,
        dim: int,
        n_experts: int = 8,
        n_shared_experts: int = 2,
        n_experts_per_tok: int = 2,
        expert_dim: int = 64,
    ):
        super().__init__()
        self.dim = dim
        self.n_experts = n_experts
        self.n_shared_experts = n_shared_experts
        self.n_experts_per_tok = n_experts_per_tok

        # Router network
        self.router = nn.Linear(dim, n_experts)

        # Expert dimensions
        self.expert_dim = expert_dim
        self.gate_dim = dim // (n_experts + n_shared_experts)

        # Routed experts (selected by router)
        self.experts = nn.ModuleList(
            [
                nn.Sequential(
                    nn.Linear(dim, expert_dim),
                    nn.GELU(),
                    nn.Linear(expert_dim, dim),
                )
                for _ in range(n_experts)
            ]
        )

        # Shared experts (always active)
        self.shared_experts = nn.ModuleList(
            [
                nn.Sequential(
                    nn.Linear(dim, expert_dim),
                    nn.GELU(),
                    nn.Linear(expert_dim, dim),
                )
                for _ in range(n_shared_experts)
            ]
        )

        # Load balancing
        self.register_buffer("expert_usage", torch.zeros(n_experts))

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: (batch, seq, dim)

        Returns:
            output: (batch, seq, dim)
            load_balance_loss: auxiliary loss for training
        """
        batch_size, seq_len, dim = x.shape

        # Router logits
        router_logits = self.router(x)  # (B, S, n_experts)

        # Top-k gating
        top_k_logits, top_k_indices = torch.topk(router_logits, self.n_experts_per_tok, dim=-1)

        # Softmax over top-k
        gates = F.softmax(top_k_logits, dim=-1)  # (B, S, k)

        # Initialize output
        output = torch.zeros_like(x)

        # Process each expert in the top-k
        for i in range(self.n_experts_per_tok):
            expert_idx = top_k_indices[:, :, i]  # (B, S)
            gate = gates[:, :, i]  # (B, S)

            # Apply each expert
            for exp_idx in range(self.n_experts):
                mask = expert_idx == exp_idx  # (B, S)

                if mask.any():
                    # Get input for this expert
                    exp_input = x[mask]  # (num_tokens, dim)
                    exp_output = self.experts[exp_idx](exp_input)  # (num_tokens, dim)

                    # Scale by gate
                    exp_gate = gate[mask].unsqueeze(-1)  # (num_tokens, 1)
                    output[mask] += exp_output * exp_gate

        # Shared experts (always active)
        for shared_exp in self.shared_experts:
            output += shared_exp(x)

        # Compute load balancing loss
        load_balance_loss = self._compute_load_balance(router_logits, top_k_indices)

        return output, load_balance_loss

    def _compute_load_balance(
        self,
        router_logits: torch.Tensor,
        top_k_indices: torch.Tensor,
    ) -> torch.Tensor:
        """Compute load balancing auxiliary loss."""
        batch_size, seq_len, _ = router_logits.shape
        num_tokens = batch_size * seq_len

        # Count expert assignments - flatten batch and seq
        top_k_flat = top_k_indices.view(-1, self.n_experts_per_tok)  # (B*S, k)

        expert_counts = torch.zeros(self.n_experts, device=router_logits.device, dtype=torch.float)

        for i in range(self.n_experts_per_tok):
            # Count how many tokens chose expert i
            expert_counts[i] = (top_k_flat[:, i] == i).sum().float()

        # Normalize
        expert_counts = expert_counts / (num_tokens * self.n_experts_per_tok) + 1e-8

        # Load balancing loss (uniform distribution)
        load_balance_loss = -(expert_counts * torch.log(expert_counts)).sum()

        return load_balance_loss


class MoELayer(nn.Module):
    """Wrapper for MoE with optional auxiliary loss."""

    def __init__(
        self,
        dim: int,
        n_experts: int = 8,
        n_shared_experts: int = 2,
        n_experts_per_tok: int = 2,
    ):
        super().__init__()
        self.moe = SparseMoE(
            dim=dim,
            n_experts=n_experts,
            n_shared_experts=n_shared_experts,
            n_experts_per_tok=n_experts_per_tok,
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.moe(x)
