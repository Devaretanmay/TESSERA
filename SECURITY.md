# Security Policy

## Supported Versions

TESSERA supports security fixes for the latest release line on supported Python versions (`3.10`-`3.12`).

## Reporting a Vulnerability

Please report vulnerabilities privately to the maintainer email listed in `pyproject.toml` or through GitHub Security Advisories if enabled.

When reporting, include:

- affected version
- reproduction steps
- impact assessment
- any proof-of-concept material

Do not open public issues for undisclosed vulnerabilities.

## Security Expectations

- Public releases are published through PyPI Trusted Publishing only.
- API bearer tokens must be stored as SHA-256 hashes via `TESSERA_API_KEYS_JSON`.
- TLS termination is required for public API deployments.
