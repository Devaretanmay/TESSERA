"""
Anthropic Claude LLM provider implementation.
"""

import os

from tessera.infra.llm.base import (
    LLMConfig,
    LLMError,
    LLMProvider,
    LLMUnavailableError,
    RiskAssessment,
    RiskLevel,
)


class AnthropicProvider(LLMProvider):
    """Anthropic Claude LLM provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._client = None
        self._initialize()

    def _initialize(self):
        """Initialize the Anthropic client."""
        api_key = self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")

        if not api_key:
            self._client = None
            return

        try:
            import anthropic

            self._client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            self._client = None

    def is_available(self) -> bool:
        """Check if Anthropic is available."""
        return self._client is not None

    def assess_risk(self, topology: dict, context: str = "") -> RiskAssessment:
        """Assess security risk using Anthropic."""
        if not self.is_available():
            raise LLMUnavailableError("Anthropic client not available")

        prompt = self._build_risk_prompt(topology, context)

        try:
            response = self._client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                system=self._get_system_prompt(),
                messages=[{"role": "user", "content": prompt}],
            )

            return self._parse_assessment(response.content[0].text)

        except Exception as e:
            raise LLMError(f"Failed to assess risk: {e}")

    def filter_false_positives(self, findings: list[dict], topology: dict) -> list[dict]:
        """Filter false positives using Anthropic."""
        if not self.is_available():
            return findings

        if not findings:
            return findings

        prompt = self._build_filter_prompt(findings, topology)

        try:
            response = self._client.messages.create(
                model=self.config.model,
                max_tokens=1024,
                temperature=self.config.temperature,
                system="You are a security expert analyzing vulnerability findings.",
                messages=[{"role": "user", "content": prompt}],
            )

            return self._parse_filtered_findings(response.content[0].text, findings)

        except Exception:
            return findings

    def close(self):
        """Close the client."""
        self._client = None

    def _get_system_prompt(self) -> str:
        return """You are TESSERA, an AI agent security scanner.
Analyze agent topology graphs for security vulnerabilities.

Respond in JSON format:
{
    "risk_level": "safe|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "explanation": "Brief explanation",
    "findings": [{"id": "...", "reason": "..."}],
    "recommendations": ["recommendation1"]
}"""

    def _build_risk_prompt(self, topology: dict, context: str) -> str:
        import json

        return f"""Analyze this agent topology for security risks:

{json.dumps(topology, indent=2)}

Context: {context}

Provide a JSON risk assessment."""

    def _build_filter_prompt(self, findings: list[dict], topology: dict) -> str:
        import json

        return f"""Analyze these findings for false positives:

Findings: {json.dumps(findings, indent=2)}

Topology: {json.dumps(topology, indent=2)}

Return JSON with ids of findings that are likely FALSE POSITIVES:
{{"false_positive_ids": ["CFPE-0001", ...]}}"""

    def _parse_assessment(self, response: str) -> RiskAssessment:
        import json
        import re

        try:
            data = json.loads(response)
            return RiskAssessment(
                risk_level=self._parse_risk_level(data.get("risk_level", "low")),
                confidence=float(data.get("confidence", 0.5)),
                explanation=data.get("explanation", ""),
                findings=data.get("findings", []),
                recommendations=data.get("recommendations", []),
            )
        except json.JSONDecodeError:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                try:
                    data = json.loads(match.group())
                    return RiskAssessment(
                        risk_level=self._parse_risk_level(data.get("risk_level", "low")),
                        confidence=float(data.get("confidence", 0.5)),
                        explanation=data.get("explanation", response),
                        findings=data.get("findings", []),
                        recommendations=data.get("recommendations", []),
                    )
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

            return RiskAssessment(
                risk_level=RiskLevel.SAFE,
                confidence=0.0,
                explanation="Could not parse LLM response",
            )

    def _parse_filtered_findings(self, response: str, original: list[dict]) -> list[dict]:
        import json
        import re

        try:
            data = json.loads(response)
            fp_ids = data.get("false_positive_ids", [])
            return [f for f in original if f.get("id") not in fp_ids]
        except json.JSONDecodeError:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                try:
                    data = json.loads(match.group())
                    fp_ids = data.get("false_positive_ids", [])
                    return [f for f in original if f.get("id") not in fp_ids]
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

        return original

    @staticmethod
    def _parse_risk_level(raw: str) -> RiskLevel:
        try:
            return RiskLevel(str(raw).lower())
        except ValueError:
            return RiskLevel.LOW
