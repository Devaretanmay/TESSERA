"""
TESSERA RDT - Full Model and Training Pipeline.
Complete TesseraRDT with Prelude + Recurrent + Coda architecture.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple
from dataclasses import dataclass

from tessera.rdt.recurrent_block import RDTBlock, RecurrentAttackBlock
from tessera.rdt.config import RDTConfig


class TesseraRDT(nn.Module):
    """
    Complete TESSERA RDT model.

    Architecture:
    - Prelude: Initial transformer layers
    - Recurrent Block: Looped RDT for multi-hop reasoning
    - Coda: Final transformer layers
    - Classifier: Vulnerability classification
    """

    def __init__(
        self,
        config: RDTConfig,
    ):
        super().__init__()
        self.config = config

        # Node embedding
        self.node_embed = nn.Embedding(config.vocab_size, config.dim)
        self.trust_embed = nn.Embedding(config.num_trust_levels, config.dim)

        # Edge embedding
        self.edge_flow_embed = nn.Embedding(config.num_data_flows, config.dim)
        self.edge_trust_embed = nn.Embedding(config.num_trust_levels, config.dim)

        # Prelude (initial encoding)
        self.prelude = nn.ModuleList(
            [
                nn.TransformerEncoderLayer(
                    d_model=config.dim,
                    nhead=config.n_heads,
                    dim_feedforward=config.hidden_dim,
                    dropout=config.dropout,
                    batch_first=True,
                )
                for _ in range(config.prelude_layers)
            ]
        )

        # Recurrent block
        self.recurrent = RDTBlock(
            dim=config.dim,
            max_loops=config.max_loop_iters,
            n_heads=config.n_heads,
            n_experts=config.n_experts,
            n_shared_experts=config.n_shared_experts,
            n_experts_per_tok=config.n_experts_per_tok,
            halting_bonus=config.halting_bonus,
            dropout=config.dropout,
        )

        # Coda (final encoding)
        self.coda = nn.ModuleList(
            [
                nn.TransformerEncoderLayer(
                    d_model=config.dim,
                    nhead=config.n_heads,
                    dim_feedforward=config.hidden_dim,
                    dropout=config.dropout,
                    batch_first=True,
                )
                for _ in range(config.coda_layers)
            ]
        )

        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(config.dim, config.dim // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.dim // 2, config.num_vuln_classes),
        )

    def forward(
        self,
        node_types: torch.Tensor,
        node_trust: torch.Tensor,
        edge_flows: torch.Tensor,
        edge_trust: torch.Tensor,
        edge_src: torch.Tensor,
        edge_dst: torch.Tensor,
        num_loops: Optional[int] = None,
    ) -> Tuple[torch.Tensor, int, torch.Tensor]:
        """
        Forward pass.

        Args:
            node_types: (batch, num_nodes) - node type indices
            node_trust: (batch, num_nodes) - trust level indices
            edge_flows: (batch, num_edges) - data flow indices
            edge_trust: (batch, num_edges) - edge trust indices
            edge_src, edge_dst: (num_edges,) - edge connectivity
            num_loops: Number of recurrent loops

        Returns:
            logits: (batch, num_nodes, num_classes)
            num_loops: loops executed
            aux_loss: auxiliary loss (stability + MoE)
        """
        batch_size, num_nodes = node_types.shape

        # 1. Node embeddings
        h = self.node_embed(node_types) + self.trust_embed(node_trust)

        # 2. Edge embeddings (for recurrence)
        edge_features = self.edge_flow_embed(edge_flows) + self.edge_trust_embed(edge_trust)

        # 3. Prelude encoding
        for layer in self.prelude:
            h = layer(h)

        # 4. Recurrent block (multi-hop reasoning)
        h, loops, aux_loss = self.recurrent(h, edge_features, num_loops)

        # 5. Coda encoding
        for layer in self.coda:
            h = layer(h)

        # 6. Classification
        logits = self.classifier(h)

        return logits, loops, aux_loss

    def predict(
        self,
        node_types: torch.Tensor,
        node_trust: torch.Tensor,
        edge_flows: torch.Tensor,
        edge_trust: torch.Tensor,
        edge_src: torch.Tensor,
        edge_dst: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get predictions and probabilities."""
        with torch.no_grad():
            logits, loops, _ = self(
                node_types, node_trust, edge_flows, edge_trust, edge_src, edge_dst
            )
            probs = F.softmax(logits, dim=-1)
            predictions = probs.argmax(dim=-1)

        return predictions, probs


class TesseraRDTTrainer:
    """Training pipeline for TesseraRDT."""

    def __init__(
        self,
        model: TesseraRDT,
        lr: float = 1e-4,
        weight_decay: float = 0.01,
        grad_clip: float = 1.0,
    ):
        self.model = model
        self.grad_clip = grad_clip

        self.optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=lr,
            weight_decay=weight_decay,
        )

        self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer,
            T_max=100,
        )

        self.device = next(model.parameters()).device

    def compute_loss(
        self,
        logits: torch.Tensor,
        targets: torch.Tensor,
        aux_loss: torch.Tensor,
        num_classes: int = 4,
    ) -> Tuple[torch.Tensor, dict]:
        """Compute multi-task loss."""
        # Classification loss
        ce_loss = F.cross_entropy(
            logits.view(-1, num_classes),
            targets.view(-1),
            reduction="mean",
        )

        # Auxiliary loss (stability + MoE)
        aux_coef = 0.1
        total_loss = ce_loss + aux_coef * aux_loss

        losses = {
            "total": total_loss,
            "ce": ce_loss,
            "aux": aux_loss,
        }

        return total_loss, losses

    def train_epoch(self, dataloader) -> dict:
        """Train one epoch."""
        self.model.train()
        total_loss = 0
        total_ce = 0
        total_aux = 0
        num_batches = 0

        for batch in dataloader:
            node_types = batch["node_types"][0].unsqueeze(0).to(self.device)
            node_trust = batch["node_trust"][0].unsqueeze(0).to(self.device)
            edge_flows = batch["edge_flows"][0].unsqueeze(0).to(self.device)
            edge_trust = batch["edge_trust"][0].unsqueeze(0).to(self.device)
            edge_src = batch["edge_src"][0].to(self.device)
            edge_dst = batch["edge_dst"][0].to(self.device)
            targets = batch["vuln_labels"].to(self.device)

            self.optimizer.zero_grad()

            logits, loops, aux_loss = self.model(
                node_types, node_trust, edge_flows, edge_trust, edge_src, edge_dst
            )

            loss, losses = self.compute_loss(logits, targets, aux_loss)

            loss.backward()

            if self.grad_clip:
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(),
                    self.grad_clip,
                )

            self.optimizer.step()

            total_loss += losses["total"].item()
            total_ce += losses["ce"].item()
            total_aux += losses["aux"].item()
            num_batches += 1

        self.scheduler.step()

        return {
            "loss": total_loss / num_batches,
            "ce": total_ce / num_batches,
            "aux": total_aux / num_batches,
            "lr": self.scheduler.get_last_lr()[0],
        }

    @torch.no_grad()
    def evaluate(self, dataloader) -> dict:
        """Evaluate model."""
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0
        num_batches = 0

        for batch in dataloader:
            node_types = batch["node_types"][0].unsqueeze(0).to(self.device)
            node_trust = batch["node_trust"][0].unsqueeze(0).to(self.device)
            edge_flows = batch["edge_flows"][0].unsqueeze(0).to(self.device)
            edge_trust = batch["edge_trust"][0].unsqueeze(0).to(self.device)
            edge_src = batch["edge_src"][0].to(self.device)
            edge_dst = batch["edge_dst"][0].to(self.device)
            targets = batch["vuln_labels"].to(self.device)

            logits, loops, aux_loss = self.model(
                node_types, node_trust, edge_flows, edge_trust, edge_src, edge_dst
            )

            loss, losses = self.compute_loss(logits, targets, aux_loss)

            preds = logits.argmax(dim=-1)
            correct += (preds == targets).sum().item()
            total += targets.numel()
            total_loss += losses["total"].item()
            num_batches += 1

        accuracy = correct / max(total, 1)

        return {
            "loss": total_loss / num_batches,
            "accuracy": accuracy,
        }


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


if __name__ == "__main__":
    print("=== Testing TesseraRDT ===")

    config = RDTConfig(
        dim=128,
        hidden_dim=256,
        n_heads=4,
        max_loop_iters=4,
        prelude_layers=1,
        coda_layers=1,
        n_experts=4,
        num_vuln_classes=4,
    )

    model = TesseraRDT(config)
    print(f"Parameters: {count_parameters(model):,}")

    # Dummy input
    bs, nodes, edges = 2, 5, 6
    node_types = torch.randint(0, 15, (bs, nodes))
    node_trust = torch.randint(0, 6, (bs, nodes))
    edge_flows = torch.randint(0, 6, (bs, edges))
    edge_trust = torch.randint(0, 6, (bs, edges))
    edge_src = torch.tensor([0, 1, 2, 3, 4, 0])
    edge_dst = torch.tensor([1, 2, 3, 4, 0, 1])
    targets = torch.randint(0, 4, (bs, nodes))

    logits, loops, aux_loss = model(
        node_types, node_trust, edge_flows, edge_trust, edge_src, edge_dst
    )

    print(f"Logits shape: {logits.shape}")
    print(f"Loops: {loops}")
    print(f"Aux loss: {aux_loss.item():.4f}")
    print("=== TesseraRDT OK ===")
