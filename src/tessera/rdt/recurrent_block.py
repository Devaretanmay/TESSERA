"""
RecurrentAttackBlock - Core RDT block for iterative attack reasoning.
LTI Stability, GraphAttention, ACT Halting, Looping.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional


class LTIStability(nn.Module):
    """LTI stability constraint from Parcae - ensures spectral radius < 1."""

    def __init__(self, dim: int, learnable_scale: bool = True):
        super().__init__()
        self.dim = dim
        self.edge_dim = dim

        if learnable_scale:
            self.log_A = nn.Parameter(torch.zeros(dim))
        else:
            self.register_buffer("log_A", torch.zeros(dim))

        self.edge_proj = nn.Linear(dim, dim)
        self.B = nn.Linear(dim, dim)

    @property
    def A(self) -> torch.Tensor:
        return -torch.exp(self.log_A)

    @property
    def spectral_radius(self) -> float:
        return torch.exp(self.log_A).abs().max().item()

    def forward(self, h: torch.Tensor, edge_features: torch.Tensor) -> torch.Tensor:
        batch_size, num_nodes, _ = h.shape
        _, num_edges, edge_dim = edge_features.shape

        if edge_dim != self.dim:
            edge_features = self.edge_proj(edge_features)

        edge_injection = self.B(edge_features)

        if num_edges != num_nodes:
            edge_injection = edge_injection.mean(dim=1, keepdim=True).expand(-1, num_nodes, -1)

        h_decay = self.A * h
        return h_decay + edge_injection

    def stability_loss(self) -> torch.Tensor:
        threshold = 0.95
        radius = self.spectral_radius
        return F.relu(torch.tensor(radius - threshold, device=self.log_A.device))


class GraphAttentionRDT(nn.Module):
    """Graph attention for RDT."""

    def __init__(self, dim: int, heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.dim = dim
        self.heads = heads
        self.head_dim = dim // heads

        self.W_q = nn.Linear(dim, dim)
        self.W_k = nn.Linear(dim, dim)
        self.W_v = nn.Linear(dim, dim)
        self.W_o = nn.Linear(dim, dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, h: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        batch_size, num_nodes, _ = h.shape

        Q = self.W_q(h).view(batch_size, num_nodes, self.heads, self.head_dim)
        K = self.W_k(h).view(batch_size, num_nodes, self.heads, self.head_dim)
        V = self.W_v(h).view(batch_size, num_nodes, self.heads, self.head_dim)

        scores = (Q @ K.transpose(-2, -1)) / (self.head_dim**0.5)

        if mask is not None:
            scores = scores.masked_fill(mask.unsqueeze(-1) == 0, float("-inf"))

        attn_weights = F.softmax(scores, dim=-1)
        attn_weights = self.dropout(attn_weights)

        output = attn_weights @ V
        output = output.contiguous().view(batch_size, num_nodes, -1)

        return self.W_o(output)


class ACTHalting(nn.Module):
    """Adaptive Computation Time halting."""

    def __init__(self, dim: int, halting_bonus: float = 0.1):
        super().__init__()
        self.halting_bonus = halting_bonus
        self.halt_net = nn.Sequential(
            nn.Linear(dim, dim // 2),
            nn.Tanh(),
            nn.Linear(dim // 2, 1),
        )

    def forward(
        self, h: torch.Tensor, cumsum_halt: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        halt_logits = self.halt_net(h).squeeze(-1)
        halt_prob = torch.sigmoid(halt_logits)

        if cumsum_halt is None:
            cumsum_halt = torch.zeros_like(halt_prob)

        active = (cumsum_halt < 0.9).float()
        cumsum_halt = cumsum_halt + halt_prob * active
        bonus = self.halting_bonus * halt_prob.mean()

        return halt_prob, active, cumsum_halt, bonus


class RecurrentAttackBlock(nn.Module):
    """Core recurrent block with LTI + Attention + MoE + ACT."""

    def __init__(
        self,
        dim: int,
        n_heads: int = 4,
        n_experts: int = 8,
        n_shared_experts: int = 2,
        n_experts_per_tok: int = 2,
        halting_bonus: float = 0.1,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.dim = dim

        self.lti = LTIStability(dim)
        self.attention = GraphAttentionRDT(dim, n_heads, dropout)

        from tessera.rdt.moe import SparseMoE

        self.moe = SparseMoE(
            dim=dim,
            n_experts=n_experts,
            n_shared_experts=n_shared_experts,
            n_experts_per_tok=n_experts_per_tok,
        )

        self.norm1 = nn.LayerNorm(dim)
        self.norm2 = nn.LayerNorm(dim)
        self.norm3 = nn.LayerNorm(dim)
        self.dropout = nn.Dropout(dropout)
        self.act = ACTHalting(dim, halting_bonus)

    def forward(
        self,
        h: torch.Tensor,
        edge_features: torch.Tensor,
        cumsum_halt: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        h_lti = self.lti(h, edge_features)
        h_lti = self.norm1(h_lti)

        h_attn = self.attention(h_lti)
        h_attn = self.dropout(h_attn)
        h = self.norm2(h_lti + h_attn)

        h_moe, moe_loss = self.moe(h)
        h_moe = self.dropout(h_moe)
        h = self.norm3(h + h_moe)

        stability_loss = self.lti.stability_loss()
        halt_prob, active, cumsum_halt, halts = self.act(h, cumsum_halt)

        return h, cumsum_halt, halt_prob, stability_loss + moe_loss


class RDTBlock(nn.Module):
    """Complete RDT block with looping."""

    def __init__(self, dim: int, max_loops: int = 8, **kwargs):
        super().__init__()
        self.dim = dim
        self.max_loops = max_loops
        self.recurrent = RecurrentAttackBlock(dim, **kwargs)

    def forward(
        self, h: torch.Tensor, edge_features: torch.Tensor, num_loops: Optional[int] = None
    ) -> Tuple[torch.Tensor, int, torch.Tensor]:
        if num_loops is None:
            num_loops = self.max_loops

        cumsum_halt = None
        total_stability_loss = 0

        for t in range(num_loops):
            h, cumsum_halt, halt_prob, stab_loss = self.recurrent(h, edge_features, cumsum_halt)
            total_stability_loss += stab_loss

        avg_stability = total_stability_loss / num_loops

        return h, num_loops, avg_stability


if __name__ == "__main__":
    print("Testing RDTBlock...")
    rdt = RDTBlock(dim=64, max_loops=2)
    h = torch.randn(2, 5, 64)
    e = torch.randn(2, 6, 64)
    h_out, loops, loss = rdt(h, e, num_loops=2)
    print(f"✓ h_out={h_out.shape}, loops={loops}, loss={loss.item():.4f}")
