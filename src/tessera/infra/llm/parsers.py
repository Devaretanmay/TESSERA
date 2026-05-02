"""
Shared LLM response parsing utilities.
Eliminates duplicate JSON parsing code across providers.
"""

import json
import re
from typing import Any


class LLMResponseParser:
    """Shared response parsing logic for LLM providers."""

    @staticmethod
    def parse_json_with_fallback(response: str) -> dict[str, Any]:
        """Parse JSON from LLM response with regex fallback."""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
        return {}

    @staticmethod
    def extract_false_positive_ids(response: str, default: list[str] | None = None) -> list[str]:
        """Extract false positive IDs from LLM response."""
        default = default or []
        data = LLMResponseParser.parse_json_with_fallback(response)
        return data.get("false_positive_ids", default)

    @staticmethod
    def extract_array_with_fallback(response: str, key: str, default: list[str] | None = None) -> list[str]:
        """Extract array field from response."""
        default = default or []
        data = LLMResponseParser.parse_json_with_fallback(response)
        return data.get(key, default)


__all__ = ["LLMResponseParser"]