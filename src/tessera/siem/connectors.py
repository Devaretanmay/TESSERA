from dataclasses import dataclass
from typing import Optional
from enum import Enum
import json
import asyncio


class SIEMProvider(str, Enum):
    SPLUNK = "splunk"
    DATADOG = "datadog"


@dataclass
class FindingEvent:
    severity: str
    title: str
    description: str
    source: str
    probe_name: Optional[str] = None
    target_path: Optional[str] = None
    indicators: Optional[list[str]] = None
    timestamp: Optional[str] = None
    metadata: Optional[dict] = None


class SplunkConnector:
    def __init__(
        self,
        url: str,
        token: str,
        index: str = "main",
        source: str = "tessera",
    ):
        self.url = url.rstrip("/")
        self.token = token
        self.index = index
        self.source = source

    async def send_event(self, event: FindingEvent) -> bool:
        payload = {
            "host": "tessera",
            "source": self.source,
            "sourcetype": "tessera_finding",
            "index": self.index,
            "time": event.timestamp,
            "event": {
                "severity": event.severity,
                "title": event.title,
                "description": event.description,
                "probe": event.probe_name,
                "target_path": event.target_path,
                "indicators": event.indicators or [],
                "metadata": event.metadata or {},
            },
        }

        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.url}/services/collector",
                    headers={"Authorization": f"Splunk {self.token}"},
                    json=payload,
                    timeout=10.0,
                )
                return resp.status_code in (200, 201)
        except Exception:
            return False

    async def send_batch(self, events: list[FindingEvent]) -> dict:
        success = 0
        failed = 0

        for event in events:
            if await self.send_event(event):
                success += 1
            else:
                failed += 1

        return {"success": success, "failed": failed}


class DatadogConnector:
    def __init__(
        self,
        api_key: str,
        site: str = "datadoghq.com",
        service: str = "tessera",
    ):
        self.api_key = api_key
        self.site = site
        self.service = service

    async def send_log(self, event: FindingEvent) -> bool:
        from datetime import datetime

        payload = {
            "ddsource": "tessera",
            "ddtags": f"severity:{event.severity},service:{self.service}",
            "hostname": "tessera",
            "message": f"[{event.severity.upper()}] {event.title}: {event.description}",
            "service": self.service,
            "title": event.title,
            "timestamp": event.timestamp or datetime.utcnow().isoformat(),
            "attributes": {
                "description": event.description,
                "probe": event.probe_name,
                "target_path": event.target_path,
                "indicators": event.indicators or [],
                "metadata": event.metadata or {},
            },
        }

        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"https://api.{self.site}/api/v1/logs",
                    headers={
                        "DD-API-KEY": self.api_key,
                        "Content-Type": "application/json",
                    },
                    json=[payload],
                    timeout=10.0,
                )
                return resp.status_code in (200, 201, 202)
        except Exception:
            return False

    async def send_batch(self, events: list[FindingEvent]) -> dict:
        success = 0
        failed = 0

        for event in events:
            if await self.send_log(event):
                success += 1
            else:
                failed += 1

        return {"success": success, "failed": failed}


def create_siem_connector(
    provider: SIEMProvider,
    **kwargs,
) -> SplunkConnector | DatadogConnector:
    if provider == SIEMProvider.SPLUNK:
        return SplunkConnector(
            url=kwargs.get("url", ""),
            token=kwargs.get("token", ""),
            index=kwargs.get("index", "main"),
        )
    elif provider == SIEMProvider.DATADOG:
        return DatadogConnector(
            api_key=kwargs.get("api_key", ""),
            site=kwargs.get("site", "datadoghq.com"),
        )
    raise ValueError(f"Unknown SIEM provider: {provider}")


async def export_findings_to_siem(
    findings: list[dict],
    provider: SIEMProvider,
    **kwargs,
) -> dict:
    connector = create_siem_connector(provider, **kwargs)

    events = []
    for f in findings:
        event = FindingEvent(
            severity=f.get("severity", "medium"),
            title=f.get("title", "TESSERA Finding"),
            description=f.get("description", ""),
            source="tessera",
            probe_name=f.get("probe"),
            target_path=f.get("path"),
            indicators=f.get("indicators"),
            metadata=f.get("metadata"),
        )
        events.append(event)

    if isinstance(connector, SplunkConnector):
        return await connector.send_batch(events)
    else:
        return await connector.send_batch(events)
