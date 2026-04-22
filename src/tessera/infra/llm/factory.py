"""
Factory for creating LLM providers.
"""

from tessera.infra.llm.base import LLMProvider, LLMConfig, ProviderType, LLMUnavailableError


def create_provider(config: LLMConfig) -> LLMProvider:
    """Create an LLM provider based on configuration.

    Args:
        config: LLM configuration

    Returns:
        LLMProvider instance

    Raises:
        LLMUnavailableError: If provider is not available
    """
    provider_type = config.provider

    if provider_type == ProviderType.OPENAI:
        from tessera.infra.llm.openai_provider import OpenAIProvider

        provider = OpenAIProvider(config)
        if not provider.is_available():
            raise LLMUnavailableError(
                "OpenAI is not available. Set OPENAI_API_KEY or install openai."
            )
        return provider

    elif provider_type == ProviderType.ANTHROPIC:
        from tessera.infra.llm.anthropic_provider import AnthropicProvider

        provider = AnthropicProvider(config)
        if not provider.is_available():
            raise LLMUnavailableError(
                "Anthropic is not available. Set ANTHROPIC_API_KEY or install anthropic."
            )
        return provider

    elif provider_type == ProviderType.OLLAMA:
        from tessera.infra.llm.ollama_provider import OllamaProvider

        provider = OllamaProvider(config)
        if not provider.is_available():
            raise LLMUnavailableError("Ollama is not available. Make sure Ollama is running.")
        return provider

    else:
        raise LLMUnavailableError(f"Unknown provider: {provider_type}")


def get_available_providers() -> list[ProviderType]:
    """Get list of available LLM providers.

    Returns:
        List of available provider types
    """
    available = []

    # Check OpenAI
    try:
        from tessera.infra.llm.openai_provider import OpenAIProvider

        p = OpenAIProvider(LLMConfig())
        if p.is_available():
            available.append(ProviderType.OPENAI)
    except Exception:
        pass

    # Check Anthropic
    try:
        from tessera.infra.llm.anthropic_provider import AnthropicProvider

        p = AnthropicProvider(LLMConfig())
        if p.is_available():
            available.append(ProviderType.ANTHROPIC)
    except Exception:
        pass

    # Check Ollama
    try:
        from tessera.infra.llm.ollama_provider import OllamaProvider

        p = OllamaProvider(LLMConfig())
        if p.is_available():
            available.append(ProviderType.OLLAMA)
    except Exception:
        pass

    return available
