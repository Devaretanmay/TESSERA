"""
Ollama LLM provider implementation (local models).
"""

from tessera.infra.llm.base import (
    LLMConfig,
    LLMError,
    LLMProvider,
    LLMUnavailableError,
    RiskAssessment,
    RiskLevel,
)
from tessera.infra.llm.parsers import LLMResponseParser


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._base_url = config.base_url or "http://localhost:11434"

    def is_available(self) -> bool:
        """Check if Ollama is available."""
        try:
            import requests

            response = requests.get(f"{self._base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def assess_risk(self, topology: dict, context: str = "") -> RiskAssessment:
        """Assess security risk using Ollama."""
        if not self.is_available():
            raise LLMUnavailableError("Ollama is not available")

        import requests

        prompt = self._build_risk_prompt(topology, context)

        try:
            response = requests.post(
                f"{self._base_url}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.max_tokens,
                    },
                },
                timeout=self.config.timeout,
            )

            if response.status_code != 200:
                raise LLMError(f"Ollama error: {response.status_code}")

            return self._parse_assessment(response.json().get("response", ""))

        except Exception as e:
            raise LLMError(f"Failed to assess risk: {e}")

    def filter_false_positives(self, findings: list[dict], topology: dict) -> list[dict]:
        """Filter false positives using Ollama."""
        if not self.is_available():
            return findings

        if not findings:
            return findings

        import requests

        prompt = self._build_filter_prompt(findings, topology)

        try:
            response = requests.post(
                f"{self._base_url}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=self.config.timeout,
            )

            if response.status_code != 200:
                return findings

            return self._parse_filtered_findings(response.json().get("response", ""), findings)

        except Exception:
            return findings

    def close(self):
        """Close connections (no-op for Ollama)."""
        pass

    def _get_system_prompt(self) -> str:
        return """You are TESSERA, an AI agent security scanner.
Analyze agent topology graphs for security vulnerabilities.

Respond in JSON format:
{
    "risk_level": "safe|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "explanation": "Brief explanation"
}"""

    def _build_risk_prompt(self, topology: dict, context: str) -> str:
        import json

        return f"""{self._get_system_prompt()}

Analyze this agent topology for security risks:

{json.dumps(topology, indent=2)}

Context: {context}

Provide a JSON risk assessment."""

    def _build_filter_prompt(self, findings: list[dict], topology: dict) -> str:
        import json

        return f"""You are a security expert analyzing vulnerability findings.

Analyze these findings for false positives:

Findings: {json.dumps(findings, indent=2)}

Topology: {json.dumps(topology, indent=2)}

Return JSON with ids of findings that are likely FALSE POSITIVES:
{{"false_positive_ids": ["CFPE-0001", ...]}}"""

    def _parse_assessment(self, response: str) -> RiskAssessment:
        """Parse LLM response into RiskAssessment."""
        data = LLMResponseParser.parse_json_with_fallback(response)

        if data:
            return RiskAssessment(
                risk_level=self._parse_risk_level(data.get("risk_level", "low")),
                confidence=float(data.get("confidence", 0.5)),
                explanation=data.get("explanation", ""),
            )

        return RiskAssessment(
            risk_level=RiskLevel.SAFE,
            confidence=0.0,
            explanation="Could not parse LLM response",
        )

    def _parse_filtered_findings(self, response: str, original: list[dict]) -> list[dict]:
        """Parse filtered findings from LLM response."""
        fp_ids = LLMResponseParser.extract_false_positive_ids(response)
        if fp_ids:
            return [f for f in original if f.get("id") not in fp_ids]
        return original

    @staticmethod
    def _parse_risk_level(raw: str) -> RiskLevel:
        try:
            return RiskLevel(str(raw).lower())
        except ValueError:
            return RiskLevel.LOW
