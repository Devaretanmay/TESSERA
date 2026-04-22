# TESSERA Deployment Guide

TESSERA's primary production surface is the public Python package and CLI. The FastAPI service is supported as a secondary deployment target for container-on-VM environments.

## Package and CLI

- Supported Python versions: `3.10`, `3.11`, `3.12`
- Operational default: `3.11`
- Release source: tagged GitHub releases published to PyPI via Trusted Publishing

Install:

```bash
python -m pip install tessera-security
tessera version
```

## API Service

Recommended topology:

1. Run the `Dockerfile` image behind a TLS-terminating reverse proxy.
2. Expose only the proxy publicly.
3. Route `/metrics` to internal monitoring only.
4. Store `TESSERA_API_KEYS_JSON` in the VM secret store or orchestrator secret manager.

Preflight the deploy host before rollout:

```bash
bash scripts/check_host_deploy.sh
```

If `gh` is authenticated, the script also checks default-branch protection and basic GitHub Actions release controls for the current repository.

Build and run:

```bash
docker build -t tessera-api .
docker run --rm -p 8000:8000 \
  -e TESSERA_API_KEYS_JSON='[{"token_sha256":"<sha256>","tenant_id":"prod","label":"default"}]' \
  tessera-api
```

Health endpoints:

- `/health/live`
- `/health/ready`
- `/metrics`

## Reverse Proxy Requirements

- Enforce HTTPS for all public traffic.
- Limit request body size to match `TESSERA_API_BODY_LIMIT_BYTES`.
- Restrict public access to `/metrics`.
- Add standard security headers and request logging at the proxy layer.

## Release and Rollback

- Release from signed/tagged commits only.
- Publish prereleases to TestPyPI first when applicable.
- Roll back API deployments by redeploying the prior container image.
- Roll back package releases by yanking the bad PyPI release and publishing a fixed version.
