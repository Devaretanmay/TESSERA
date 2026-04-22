# TESSERA Release Playbook

## Branch Protection Expectations

- Require CI to pass before merge.
- Restrict direct pushes to `main`.
- Create releases from version tags only.
- Use GitHub environments or equivalent approval controls for release jobs.

## Versioning

- Use semantic versioning.
- Patch releases for bug fixes and hardening changes.
- Minor releases for new rules or backward-compatible API additions.
- Major releases for breaking CLI, Python API, or output contract changes.

## Release Flow

1. Update version metadata and release notes.
2. Merge to `main` with all required checks green.
3. Tag the release as `vX.Y.Z`.
4. Let the GitHub release workflow build, attest, generate SBOMs, and publish.
5. Verify the published package with a fresh install and CLI smoke test.

## Prereleases

- Use tags such as `vX.Y.Zrc1`, `vX.Y.Zb1`, or `vX.Y.Za1`.
- Prerelease tags publish to TestPyPI through the release workflow.
- Do not promote prerelease artifacts to production documentation or support commitments.

## Rollback

- Yank broken public releases.
- Publish a fixed replacement version instead of force-replacing artifacts.
- Document the incident in the runbook and changelog.
