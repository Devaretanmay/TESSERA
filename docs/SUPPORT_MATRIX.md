# TESSERA Support Matrix

## Supported Python Versions

- Supported: `3.10`, `3.11`, `3.12`
- Operational default: `3.11`
- Not currently claimed as supported: `3.13+`

## Supported Surfaces

- Primary production surface: public package and CLI
- Secondary production surface: FastAPI service behind a reverse proxy in container-on-VM deployments

## Compatibility Commitments

- Stable in this release line:
  - `tessera scan`, `topology`, `list-rules`, `explain`, `version`
  - `Tesseract`, `scan()`, `scan_to_dict()`, `OutputFormat`
  - CFPE rule IDs
- JSON output keys are treated as versioned public interface.
- `core.detection.patterns` remains as a compatibility facade while canonical detection lives in `core.detection.rules`.
