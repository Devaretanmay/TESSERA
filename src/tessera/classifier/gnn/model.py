from dataclasses import dataclass
from typing import Optional
import numpy as np


@dataclass
class GNNConfig:
    input_dim: int = 16
    hidden_dim: int = 64
    output_dim: int = 32
    num_layers: int = 3
    dropout: float = 0.2


class GraphSAGEModel:
    def __init__(self, config: Optional[GNNConfig] = None):
        self.config = config or GNNConfig()
        self._initialized = False
        self._weights = None

    def _init_weights(self):
        if self._initialized:
            return

        # Xavier/Glorot initialization for better training
        self._weights = {}
        for i in range(self.config.num_layers):
            in_dim = self.config.input_dim if i == 0 else self.config.hidden_dim
            out_dim = (
                self.config.hidden_dim if i < self.config.num_layers - 1 else self.config.output_dim
            )

            # Weight for self-features
            self._weights[f"W_self_{i}"] = np.random.randn(in_dim, out_dim) * np.sqrt(
                2.0 / (in_dim + out_dim)
            )
            # Weight for neighbor-features
            self._weights[f"W_neigh_{i}"] = np.random.randn(in_dim, out_dim) * np.sqrt(
                2.0 / (in_dim + out_dim)
            )
            # Bias
            self._weights[f"b_{i}"] = np.zeros(out_dim)
        self._initialized = True

    def _relu(self, x: np.ndarray) -> np.ndarray:
        return np.maximum(0, x)

    def _dropout(self, x: np.ndarray) -> np.ndarray:
        if self.config.dropout == 0:
            return x
        mask = np.random.rand(*x.shape) > self.config.dropout
        return x * mask / (1 - self.config.dropout)

    def forward(self, features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        self._init_weights()
        self._cache = {"h_0": features}

        h = features
        for i in range(self.config.num_layers):
            # Self transformation
            h_self = np.dot(h, self._weights[f"W_self_{i}"])

            # Neighbor aggregation
            adj_with_self = adjacency + np.eye(adjacency.shape[0])
            deg = np.sum(adj_with_self, axis=1, keepdims=True)
            deg[deg == 0] = 1
            neighbor_agg = (adj_with_self @ h) / deg

            # Neighbor transformation
            h_neigh = np.dot(neighbor_agg, self._weights[f"W_neigh_{i}"])

            # Combine
            z = h_self + h_neigh + self._weights[f"b_{i}"]
            self._cache[f"z_{i}"] = z
            self._cache[f"neigh_agg_{i}"] = neighbor_agg

            # Apply nonlinearity
            h = self._relu(z)
            self._cache[f"h_{i+1}"] = h

        return h

    def backward(self, d_loss_d_h: np.ndarray, learning_rate: float = 0.01):
        """Simple backprop for GNN weights."""
        if not self._initialized or not hasattr(self, "_cache"):
            return

        dh = d_loss_d_h
        for i in reversed(range(self.config.num_layers)):
            z = self._cache[f"z_{i}"]
            h_prev = self._cache[f"h_{i}"]
            neigh_agg = self._cache[f"neigh_agg_{i}"]

            # Gradient through ReLU
            dz = dh * (z > 0)

            # Gradients for weights
            dw_self = np.dot(h_prev.T, dz)
            dw_neigh = np.dot(neigh_agg.T, dz)
            db = np.sum(dz, axis=0)

            # Gradient for previous layer
            # Need to account for adjacency in neighbor gradient
            # dh_prev = dz @ W_self^T + (A^T @ dz) @ W_neigh^T
            # (Simplified for now: just dz @ W_self^T)
            dh = np.dot(dz, self._weights[f"W_self_{i}"].T)

            # Update weights
            self._weights[f"W_self_{i}"] -= learning_rate * dw_self
            self._weights[f"W_neigh_{i}"] -= learning_rate * dw_neigh
            self._weights[f"b_{i}"] -= learning_rate * db

    def predict(self, features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        """Get node embeddings from the GNN."""
        embeddings = self.forward(features, adjacency)
        return embeddings

    def get_node_embeddings(self, features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        """Alias for predict for clarity."""
        return self.predict(features, adjacency)


class CompoundFailureClassifier:
    def __init__(self, gnn_model: Optional[GraphSAGEModel] = None):
        self.gnn = gnn_model or GraphSAGEModel()
        self.classifier_weights = None
        self._trained = False

    def _init_classifier(self):
        if self.classifier_weights is None:
            self.classifier_weights = {
                "W": np.random.randn(32, 4) * 0.01,
                "b": np.zeros(4),
            }

    def classify(
        self,
        features: np.ndarray,
        adjacency: np.ndarray,
    ) -> dict:
        embeddings = self.gnn.predict(features, adjacency)

        self._init_classifier()
        logits = np.dot(embeddings, self.classifier_weights["W"]) + self.classifier_weights["b"]
        probs = self._softmax(logits)

        classes = ["safe", "atomic_injection", "chain_exploitation", "exfiltration"]
        predictions = np.argmax(probs, axis=1)

        results = []
        for i, pred in enumerate(predictions):
            results.append(
                {
                    "node_id": i,
                    "class": classes[pred],
                    "confidence": float(probs[i, pred]),
                    "probabilities": {c: float(p) for c, p in zip(classes, probs[i])},
                }
            )

        return {
            "predictions": results,
            "graph_embedding": embeddings.mean(axis=0).tolist(),
        }

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=1, keepdims=True)

    def train(
        self,
        features: list[np.ndarray],
        adjacency_matrices: list[np.ndarray],
        labels: list[int],
        epochs: int = 100,
    ) -> dict:
        self._init_classifier()
        self._trained = True

        losses = []
        for epoch in range(epochs):
            epoch_loss = 0
            for feat, adj, label in zip(features, adjacency_matrices, labels):
                embeddings = self.gnn.predict(feat, adj)
                logits = (
                    np.dot(embeddings, self.classifier_weights["W"]) + self.classifier_weights["b"]
                )
                probs = self._softmax(logits)

                label_onehot = np.zeros(4)
                label_onehot[label] = 1

                loss = -np.sum(label_onehot * np.log(probs + 1e-8))
                epoch_loss += loss

                grad_w = np.outer(embeddings[0], probs[0] - label_onehot)
                grad_b = probs[0] - label_onehot

                lr = 0.01
                self.classifier_weights["W"] -= lr * grad_w
                self.classifier_weights["b"] -= lr * grad_b

            losses.append(epoch_loss / len(labels))

        return {"epochs": epochs, "final_loss": losses[-1], "loss_curve": losses}


def create_gnn_classifier() -> CompoundFailureClassifier:
    return CompoundFailureClassifier()
