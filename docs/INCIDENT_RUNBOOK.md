# TESSERA Incident and Rollback Runbook

## Severity Triggers

- Release artifact fails smoke install or CLI validation
- API returns elevated `5xx` or `429` unexpectedly
- Metrics show repeated auth failures, validation spikes, or LLM provider instability
- Security report indicates token leakage or vulnerable dependency

## Immediate Response

1. Freeze new releases and deployments.
2. Capture affected version, tag, commit, and environment.
3. Review `/metrics`, structured logs, and recent CI/release jobs.
4. Disable compromised API keys by removing their hashes from `TESSERA_API_KEYS_JSON`.

## Package Rollback

1. Yank the affected release on PyPI.
2. Prepare a fixed patch release with a new version.
3. Re-run CI, build, and smoke-install checks.
4. Publish the fixed version through the release workflow.

## API Rollback

1. Redeploy the previous known-good container image.
2. Confirm `/health/ready` and `/metrics` recover.
3. Validate a known-safe scan request end to end.

## Post-Incident Actions

1. Add or extend a regression test.
2. Update release notes and incident timeline.
3. Rotate impacted credentials or tokens.
