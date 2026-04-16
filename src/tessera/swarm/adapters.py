from dataclasses import dataclass
from typing import Protocol
import os
import httpx


class BackboneAdapter(Protocol):
    async def generate(self, prompt: str, **kwargs) -> str: ...
    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str: ...
    def get_cost_estimate(self, prompt: str) -> float: ...
    def get_model_name(self) -> str: ...
    async def close(self) -> None: ...


@dataclass
class OllamaAdapter(BackboneAdapter):
    base_url: str = "http://localhost:11434"
    model: str = "llama3:8b"
    temperature: float = 0.7

    async def generate(self, prompt: str, **kwargs) -> str:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": kwargs.get("temperature", self.temperature)},
                    },
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json().get("response", "")
        except Exception as e:
            return f"[Ollama unavailable: {e}]"

    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str:
        full = "\n".join([f"{m['role']}: {m['content']}" for m in context]) + f"\nuser: {prompt}"
        return await self.generate(full, **kwargs)

    def get_cost_estimate(self, prompt: str) -> float:
        return 0.0

    def get_model_name(self) -> str:
        return self.model

    async def close(self) -> None:
        pass


@dataclass
class ChatAdapter(BackboneAdapter):
    model: str = "gpt-4o-mini"
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    timeout: float = 60.0

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _msgs(self, prompt: str, ctx: list[dict] | None = None) -> list[dict]:
        return [{"role": m["role"], "content": m["content"]} for m in (ctx or [])] + [
            {"role": "user", "content": prompt}
        ]

    async def generate(self, prompt: str, **kwargs) -> str:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json={"model": self.model, "messages": [{"role": "user", "content": prompt}]},
                    headers=self._auth(),
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return f"[Error: {e}]"

    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json={"model": self.model, "messages": self._msgs(prompt, context)},
                    headers=self._auth(),
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return f"[Error: {e}]"

    def get_cost_estimate(self, prompt: str) -> float:
        return len(prompt) // 4 * 0.00001

    def get_model_name(self) -> str:
        return self.model

    async def close(self) -> None:
        pass


class OpenAIAdapter(ChatAdapter):
    def __post_init__(self):
        self.api_key = self.api_key or os.environ.get("OPENAI_API_KEY")


class GroqAdapter(ChatAdapter):
    def __post_init__(self):
        self.api_key = self.api_key or os.environ.get("GROQ_API_KEY")
        self.base_url = "https://api.groq.com/openai/v1"

    def get_cost_estimate(self, prompt: str) -> float:
        rates = {"llama-3.3-70b-versatile": 0.0002, "llama-3.1-8b-instant": 0.00004}
        return len(prompt) // 4 * rates.get(self.model, 0.0001)


class AnthropicAdapter(BackboneAdapter):
    model: str = "claude-3-haiku-20240307"
    api_key: str | None = None

    def __post_init__(self):
        self.api_key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")

    async def generate(self, prompt: str, **kwargs) -> str:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    json={
                        "model": self.model,
                        "max_tokens": 512,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                    timeout=60.0,
                )
                resp.raise_for_status()
                return resp.json().get("content", [{}])[0].get("text", "")
        except Exception as e:
            return f"[Anthropic unavailable: {e}]"

    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str:
        msgs = [{"role": m["role"], "content": m["content"]} for m in context] + [
            {"role": "user", "content": prompt}
        ]
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    json={"model": self.model, "max_tokens": 512, "messages": msgs},
                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                    timeout=60.0,
                )
                resp.raise_for_status()
                return resp.json().get("content", [{}])[0].get("text", "")
        except Exception as e:
            return f"[Anthropic unavailable: {e}]"

    def get_cost_estimate(self, prompt: str) -> float:
        return len(prompt) // 4 * 0.000025

    def get_model_name(self) -> str:
        return self.model

    async def close(self) -> None:
        pass


def create_backbone(provider: str = "ollama", **kwargs) -> BackboneAdapter | None:
    adapters = {
        "ollama": OllamaAdapter,
        "openai": OpenAIAdapter,
        "groq": GroqAdapter,
        "anthropic": AnthropicAdapter,
    }
    return adapters.get(provider)(**kwargs) if provider in adapters else None
