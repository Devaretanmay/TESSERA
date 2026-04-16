from dataclasses import dataclass
from typing import Protocol
import os


class BackboneAdapter(Protocol):
    async def generate(self, prompt: str, **kwargs) -> str: ...
    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str: ...
    def get_cost_estimate(self, prompt: str) -> float: ...
    def get_model_name(self) -> str: ...
    @property
    def supports_streaming(self) -> bool: ...

    async def close(self) -> None: ...


@dataclass
class OllamaAdapter:
    base_url: str = "http://localhost:11434"
    model: str = "llama3:8b"
    temperature: float = 0.7
    _session = None

    async def generate(self, prompt: str, **kwargs) -> str:
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": kwargs.get("temperature", self.temperature),
                            "num_predict": kwargs.get("max_tokens", 512),
                        },
                    },
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json().get("response", "")
        except Exception as e:
            return f"[Ollama unavailable: {e}]"

    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str:
        full_prompt = "\n".join([f"{m['role']}: {m['content']}" for m in context])
        full_prompt += f"\nuser: {prompt}"
        return await self.generate(full_prompt, **kwargs)

    def get_cost_estimate(self, prompt: str) -> float:
        return 0.0

    def get_model_name(self) -> str:
        return self.model

    @property
    def supports_streaming(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@dataclass
class OpenAIAdapter:
    model: str = "gpt-4o-mini"
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    temperature: float = 0.7
    _client = None

    def __post_init__(self):
        self.api_key = self.api_key or os.environ.get("OPENAI_API_KEY")

    async def generate(self, prompt: str, **kwargs) -> str:
        try:
            import httpx

            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": kwargs.get("temperature", self.temperature),
                    },
                    headers=headers,
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return f"[OpenAI unavailable: {e}]"

    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str:
        messages = [{"role": m["role"], "content": m["content"]} for m in context]
        messages.append({"role": "user", "content": prompt})

        try:
            import httpx

            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json={
                        "model": self.model,
                        "messages": messages,
                        "temperature": kwargs.get("temperature", self.temperature),
                    },
                    headers=headers,
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            return f"[OpenAI unavailable: {e}]"

    def get_cost_estimate(self, prompt: str) -> float:
        tokens = len(prompt) // 4
        pricing = {
            "gpt-4o": 0.0025,
            "gpt-4o-mini": 0.00001,
            "gpt-4-turbo": 0.0015,
            "gpt-3.5-turbo": 0.00002,
        }
        rate = pricing.get(self.model, 0.00001)
        return tokens * rate

    def get_cost_display(self, prompt: str) -> str:
        cost = self.get_cost_estimate(prompt)
        return f"${cost:.4f}"

    def get_model_name(self) -> str:
        return self.model

    @property
    def supports_streaming(self) -> bool:
        return True

    async def close(self) -> None:
        pass


@dataclass
class AnthropicAdapter:
    model: str = "claude-3-haiku-20240307"
    api_key: str | None = None
    temperature: float = 0.7

    def __post_init__(self):
        self.api_key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")

    async def generate(self, prompt: str, **kwargs) -> str:
        try:
            import httpx

            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    json={
                        "model": self.model,
                        "max_tokens": kwargs.get("max_tokens", 512),
                        "messages": [{"role": "user", "content": prompt}],
                    },
                    headers=headers,
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json().get("content", [{}])[0].get("text", "")
        except Exception as e:
            return f"[Anthropic unavailable: {e}]"

    async def generate_with_context(self, prompt: str, context: list[dict], **kwargs) -> str:
        messages = [{"role": m["role"], "content": m["content"]} for m in context]
        messages.append({"role": "user", "content": prompt})

        try:
            import httpx

            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    json={
                        "model": self.model,
                        "max_tokens": kwargs.get("max_tokens", 512),
                        "messages": messages,
                    },
                    headers=headers,
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json().get("content", [{}])[0].get("text", "")
        except Exception as e:
            return f"[Anthropic unavailable: {e}]"

    def get_cost_estimate(self, prompt: str) -> float:
        tokens = len(prompt) // 4
        return tokens * 0.000025

    def get_model_name(self) -> str:
        return self.model

    @property
    def supports_streaming(self) -> bool:
        return True

    async def close(self) -> None:
        pass


def create_backbone(provider: str = "ollama", **kwargs) -> BackboneAdapter | None:
    if provider == "ollama":
        return OllamaAdapter(**kwargs)
    elif provider == "openai":
        return OpenAIAdapter(**kwargs)
    elif provider == "anthropic":
        return AnthropicAdapter(**kwargs)
    return None
