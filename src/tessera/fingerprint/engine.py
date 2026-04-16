from dataclasses import dataclass, field
from typing import Literal
from enum import Enum
import numpy as np


class DriftMethod(str, Enum):
    MMD = "mmd"
    KL_DIVERGENCE = "kl_divergence"
    JS_DIVERGENCE = "js_divergence"
    COSINE_DISTANCE = "cosine_distance"


@dataclass
class EmbeddingSample:
    text: str
    embedding: np.ndarray | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class BehavioralFingerprint:
    mean_embedding: np.ndarray
    std_embedding: np.ndarray
    distribution: dict
    sample_count: int
    created_at: str

    def to_dict(self) -> dict:
        return {
            "mean_embedding": self.mean_embedding.tolist(),
            "std_embedding": self.std_embedding.tolist(),
            "distribution": self.distribution,
            "sample_count": self.sample_count,
            "created_at": self.created_at,
        }


class DriftDetector:
    method: DriftMethod = DriftMethod.COSINE_DISTANCE
    threshold: float = 0.15

    def __init__(self, method: DriftMethod = DriftMethod.COSINE_DISTANCE, threshold: float = 0.15):
        self.method = method
        self.threshold = threshold

    def compute_mmd(self, X: list[np.ndarray], Y: list[np.ndarray]) -> float:
        if not X or not Y:
            return 0.0

        X = np.array(X)
        Y = np.array(Y)

        mean_x = np.mean(X, axis=0)
        mean_y = np.mean(Y, axis=0)

        var_x = np.var(X, axis=0)
        var_y = np.var(Y, axis=0)

        mmd_squared = np.mean(var_x) + np.mean(var_y) - 2 * np.mean((mean_x - mean_y) ** 2)

        return np.sqrt(max(mmd_squared, 0.0))

    def compute_cosine_distance(self, X: list[np.ndarray], Y: list[np.ndarray]) -> float:
        if not X or not Y:
            return 0.0

        X_mean = np.mean(X, axis=0)
        Y_mean = np.mean(Y, axis=0)

        dot_product = np.dot(X_mean, Y_mean)
        norm_x = np.linalg.norm(X_mean)
        norm_y = np.linalg.norm(Y_mean)

        if norm_x == 0 or norm_y == 0:
            return 0.0

        cosine_similarity = dot_product / (norm_x * norm_y)
        return 1.0 - cosine_similarity

    def detect(
        self,
        current_samples: list[np.ndarray],
        baseline: BehavioralFingerprint,
    ) -> dict:
        if self.method == DriftMethod.MMD:
            baseline_samples = [baseline.mean_embedding]
            mmd = self.compute_mmd(current_samples, baseline_samples)
            is_drift = mmd > self.threshold
            score = mmd
        else:
            score = self.compute_cosine_distance(current_samples, [baseline.mean_embedding])
            is_drift = score > self.threshold

        return {
            "mmd_score" if self.method == DriftMethod.MMD else "drift_score": score,
            "is_drift": is_drift,
            "threshold": self.threshold,
            "method": self.method.value,
            "recommended_action": "alert" if is_drift else "none",
        }


class FingerprintCalibrator:
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"

    async def embed(self, texts: list[str]) -> list[np.ndarray]:
        try:
            from sentence_transformers import SentenceTransformer

            model = SentenceTransformer(self.model_name)
            embeddings = model.encode(texts)
            return [e for e in embeddings]
        except ImportError:
            return [np.random.rand(384) for _ in texts]
        except Exception:
            return [np.zeros(384) for _ in texts]

    async def calibrate(
        self,
        samples: dict[str, list[str]],
    ) -> BehavioralFingerprint:
        from datetime import datetime

        all_texts = []
        for category, texts in samples.items():
            all_texts.extend(texts)

        embeddings = await self.embed(all_texts)
        embedding_arrays = np.array(embeddings)

        mean_emb = np.mean(embedding_arrays, axis=0)
        std_emb = np.std(embedding_arrays, axis=0)

        distribution = {}
        for category, texts in samples.items():
            cat_embeddings = await self.embed(texts)
            cat_emb = np.array(cat_embeddings)
            distribution[category] = {
                "mean": np.percentile(cat_emb, 50, axis=0).tolist(),
                "p5": np.percentile(cat_emb, 5, axis=0).tolist(),
                "p95": np.percentile(cat_emb, 95, axis=0).tolist(),
            }

        return BehavioralFingerprint(
            mean_embedding=mean_emb,
            std_embedding=std_emb,
            distribution=distribution,
            sample_count=len(all_texts),
            created_at=datetime.utcnow().isoformat(),
        )


class FingerprintEngine:
    calibrator: FingerprintCalibrator
    detector: DriftDetector
    baseline: BehavioralFingerprint | None = None

    def __init__(
        self,
        method: DriftMethod = DriftMethod.COSINE_DISTANCE,
        threshold: float = 0.15,
    ):
        self.calibrator = FingerprintCalibrator()
        self.detector = DriftDetector(method, threshold)

    async def create_baseline(
        self,
        samples: dict[str, list[str]],
    ) -> BehavioralFingerprint:
        self.baseline = await self.calibrator.calibrate(samples)
        return self.baseline

    async def check_drift(
        self,
        responses: list[str],
        webhook_url: str | None = None,
    ) -> dict:
        if not self.baseline:
            return {"error": "No baseline established"}

        embeddings = await self.calibrator.embed(responses)

        result = self.detector.detect(embeddings, self.baseline)

        if result["recommended_action"] == "alert" and webhook_url:
            await self._send_alert(webhook_url, result)

        return result

    async def _send_alert(self, webhook_url: str, drift_result: dict) -> bool:
        import aiohttp
        import datetime

        payload = {
            "alert_type": "behavioral_drift",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "drift_score": drift_result.get("mmd_score") or drift_result.get("drift_score"),
            "threshold": drift_result["threshold"],
            "method": drift_result["method"],
            "severity": "high"
            if drift_result.get("mmd_score", 0) > self.detector.threshold * 2
            else "medium",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status < 400
        except Exception:
            return False

    def save_baseline(self, path: str) -> None:
        if not self.baseline:
            return
        import json

        with open(path, "w") as f:
            json.dump(self.baseline.to_dict(), f)

    def load_baseline(self, path: str) -> None:
        import json

        with open(path) as f:
            data = json.load(f)
        self.baseline = BehavioralFingerprint(
            mean_embedding=np.array(data["mean_embedding"]),
            std_embedding=np.array(data["std_embedding"]),
            distribution=data["distribution"],
            sample_count=data["sample_count"],
            created_at=data["created_at"],
        )
