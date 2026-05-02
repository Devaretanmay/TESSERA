from __future__ import annotations

import hashlib
import importlib

from fastapi.testclient import TestClient

from tessera.infra.api.config import get_api_settings


SAFE_TOPOLOGY = """
system: safe
version: "1.0"
nodes:
  - id: user
    type: user
    trust_boundary: external
  - id: llm
    type: llm
    trust_boundary: internal
edges:
  - from: user
    to: llm
    flow: api
    trust_boundary: external
"""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _load_server(monkeypatch, **env):
    counter = getattr(_load_server, "_counter", 0) + 1
    _load_server._counter = counter
    defaults = {
        "TESSERA_API_KEYS_JSON": (
            '[{"token_sha256":"%s","tenant_id":"tenant-test-%d","label":"primary-%d"}]'
            % (_hash_token("secret-token"), counter, counter)
        ),
        "TESSERA_API_RATE_LIMIT_PER_MINUTE": "60",
        "TESSERA_API_BODY_LIMIT_BYTES": "262144",
        "TESSERA_API_MAX_TOPOLOGY_NODES": "200",
        "TESSERA_API_MAX_TOPOLOGY_EDGES": "500",
    }
    defaults.update(env)
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)
    get_api_settings.cache_clear()
    import tessera.infra.api.server as server

    return importlib.reload(server)


def test_api_scan_requires_bearer_token(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    response = client.post("/api/v1/scans", json={"topology_yaml": SAFE_TOPOLOGY})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authorization_invalid"


def test_api_scan_accepts_inline_topology_yaml(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    response = client.post(
        "/api/v1/scans",
        json={"topology_yaml": SAFE_TOPOLOGY, "output_format": "json"},
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["findings_count"] == 1
    assert body["results"]["format"] == "json"
    assert body["results"]["document"]["summary"]["total"] == 1


def test_api_rejects_legacy_topology_path_contract(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    response = client.post(
        "/api/v1/scans",
        json={"topology_path": "examples/safe_agent.yaml"},
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_api_enforces_body_size_limit(monkeypatch):
    server = _load_server(monkeypatch, TESSERA_API_BODY_LIMIT_BYTES="32")
    client = TestClient(server.app)

    response = client.post(
        "/api/v1/scans",
        json={"topology_yaml": SAFE_TOPOLOGY},
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_api_enforces_topology_node_limit(monkeypatch):
    server = _load_server(monkeypatch, TESSERA_API_MAX_TOPOLOGY_NODES="1")
    client = TestClient(server.app)

    response = client.post(
        "/api/v1/scans",
        json={"topology_yaml": SAFE_TOPOLOGY},
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_failed"


def test_api_enforces_rate_limit(monkeypatch):
    server = _load_server(monkeypatch, TESSERA_API_RATE_LIMIT_PER_MINUTE="1")
    client = TestClient(server.app)
    headers = {"Authorization": "Bearer secret-token"}

    first = client.post("/api/v1/scans", json={"topology_yaml": SAFE_TOPOLOGY}, headers=headers)
    second = client.post("/api/v1/scans", json={"topology_yaml": SAFE_TOPOLOGY}, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limit_exceeded"


def test_api_internal_failures_do_not_leak_stack_details(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    def fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(server.Tessera, "build_scan_result", fail)
    response = client.post(
        "/api/v1/scans",
        json={"topology_yaml": SAFE_TOPOLOGY},
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_failure"
    assert "boom" not in response.text


def test_health_and_metrics_endpoints(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200

    response = client.post(
        "/api/v1/scans",
        json={"topology_yaml": SAFE_TOPOLOGY},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert response.status_code == 200

    metrics_response = client.get("/metrics")
    assert metrics_response.status_code == 200
    assert "tessera_requests_total" in metrics_response.text
