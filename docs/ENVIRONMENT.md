# TESSERA Environment Reference

## Core

- `TESSERA_LOG_LEVEL`
  Default: `INFO` for API deployments, `WARNING` for CLI
- `TESSERA_API_JSON_LOGS`
  Default: `true`

## API Runtime

- `TESSERA_API_HOST`
  Default: `0.0.0.0`
- `TESSERA_API_PORT`
  Default: `8000`
- `TESSERA_API_WORKERS`
  Default: `2` in the Docker entrypoint
- `TESSERA_API_BODY_LIMIT_BYTES`
  Default: `262144`
- `TESSERA_API_MAX_TOPOLOGY_NODES`
  Default: `200`
- `TESSERA_API_MAX_TOPOLOGY_EDGES`
  Default: `500`
- `TESSERA_API_RATE_LIMIT_PER_MINUTE`
  Default: `60`
- `TESSERA_API_RATE_LIMIT_WINDOW_SECONDS`
  Default: `60`
- `TESSERA_API_SCAN_TIMEOUT_SECONDS`
  Default: `15`
- `TESSERA_LLM_TIMEOUT_SECONDS`
  Default: `30`

## API Authentication

- `TESSERA_API_KEYS_JSON`
  JSON array of active bearer-token descriptors. Tokens are stored as SHA-256 hashes.

Example:

```json
[
  {
    "token_sha256": "a7d3f6c2...",
    "tenant_id": "prod",
    "label": "primary",
    "rate_limit_per_minute": 120,
    "rate_limit_bucket": "default"
  }
]
```

Generate a token hash:

```bash
python - <<'PY'
import hashlib
print(hashlib.sha256(b"replace-with-real-token").hexdigest())
PY
```

## LLM Provider Secrets

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

Only set these when LLM-assisted analysis is intentionally enabled.
