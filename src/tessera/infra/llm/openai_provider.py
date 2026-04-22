"""
OpenAI LLM provider implementation.
"""

import os
from typing import Any

from tessera.infra.llm.base import (
    LLMProvider,
    LLMConfig,
    LLMUnavailableError,
    RiskAssessment,
    RiskLevel,
)


class OpenAIProvider(LLMProvider):
    """OpenAI LLM provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._client = None
        self._initialize()

    def _initialize(self):
        """Initialize the OpenAI client."""
        api_key = self.config.api_key or os.environ.get("OPENAI_API_KEY")

        if not api_key:
            self._client = None
            return

        try:
            from openai import OpenAI

            self._client = OpenAI(api_key=api_key, base_url=self.config.base_url)
        except ImportError:
            self._client = None

    def is_available(self) -> bool:
        """Check if OpenAI is available."""
        return self._client is not None

    def assess_risk(self, topology: dict, context: str = "") -> RiskAssessment:
        """Assess security risk using OpenAI."""
        if not self.is_available():
            raise LLMUnavailableError("OpenAI client not available")

        # Build prompt for risk assessment
        prompt = self._build_risk_prompt(topology, context)

        try:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.timeout,
            )

            return self._parse_assessment(response.choices[0].message.content)

        except Exception as e:
            raise LLMError(f"Failed to assess risk: {e}")

    def filter_false_positives(self, findings: list[dict], topology: dict) -> list[dict]:
        """Filter false positives using OpenAI."""
        if not self.is_available():
            return findings

        if not findings:
            return findings

        prompt = self._build_filter_prompt(findings, topology)

        try:
            response = self._client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert analyzing vulnerability findings. Determine which are likely false positives.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )

            return self._parse_filtered_findings(response.choices[0].message.content, findings)

        except Exception as e:
            # Return original findings on error
            return findings

    def close(self):
        """Close the client (no-op for OpenAI)."""
        self._client = None

    def _get_system_prompt(self) -> str:
        """Get the system prompt for security analysis."""
        return """You are TESSERA, an AI agent security scanner. 
Analyze agent topology graphs for security vulnerabilities.

Respond in JSON format:
{
    "risk_level": "safe|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "explanation": "Brief explanation",
    "findings": [{"id": "...", "reason": "..."}],
    "recommendations": ["recommendation1", "recommendation2"]
}

Focus on:
1. Prompt injection risks
2. Data exfiltration paths
3. Trust boundary crossings
4. Tool chaining vulnerabilities
5. Memory poisoning"""

    def _build_risk_prompt(self, topology: dict, context: str) -> str:
        """Build the risk assessment prompt."""
        import json

        return f"""Analyze this agent topology for security risks:

{json.dumps(topology, indent=2)}

Context: {context}

Provide a JSON risk assessment."""

    def _build_filter_prompt(self, findings: list[dict], topology: dict) -> str:
        """Build the false positive filtering prompt."""
        import json

        return f"""Analyze these findings for false positives:

Findings: {json.dumps(findings, indent=2)}

Topology: {json.dumps(topology, indent=2)}

Return JSON with ids of findings that are likely FALSE POSITIVES:
{{"false_positive_ids": ["CFPE-0001", ...]}}"""

    def _parse_assessment(self, response: str) -> RiskAssessment:
        """Parse LLM response into RiskAssessment."""
        import json

        try:
            # Try to extract JSON from response
            data = json.loads(response)

            return RiskAssessment(
                risk_level=RiskLevel(data.get("risk_level", "low")),
                confidence=float(data.get("confidence", 0.5)),
                explanation=data.get("explanation", ""),
                findings=data.get("findings", []),
                recommendations=data.get("recommendations", []),
            )
        except json.JSONDecodeError:
            # Try to find JSON in response
            import re

            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                try:
                    data = json.loads(match.group())
                    return RiskAssessment(
                        risk_level=RiskLevel(data.get("risk_level", "low")),
                        confidence=float(data.get("confidence", 0.5)),
                        explanation=data.get("explanation", response),
                        findings=data.get("findings", []),
                        recommendations=data.get("recommendations", []),
                    )
                except:
                    pass

            # Default to safe on parse failure
            return RiskAssessment(
                risk_level=RiskLevel.SAFE,
                confidence=0.0,
                explanation="Could not parse LLM response",
            )

    def _parse_filtered_findings(self, response: str, original: list[dict]) -> list[dict]:
        """Parse filtered findings from LLM response."""
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
                except:
                    pass

        return original
