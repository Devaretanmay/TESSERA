# Changelog

All notable changes to TESSERA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-04-17

### Added
- Clean production architecture: core/engine/infra/interfaces separation
- CFPE-0001: RAG to Tool chain detection
- CFPE-0002: Memory poisoning detection  
- CFPE-0004: Trust boundary bypass detection
- SQLite persistence for scan history
- FastAPI server with API key authentication
- CLI with scan, topology, findings, scans, server commands

### Fixed
- Detection patterns logic corrected
- Partial scan ID resolution for findings command
- Database persistence (was dropping tables on init)

### Changed
- Restructured from prototype to production layout
- Removed experimental/dead code

## [1.0.0] - 2026-04-?? - [YANKED]

### Added
- Initial release (prototype phase)

### Removed
- This version is no longer available.

## [1.0.0-beta] - [YANKED]

Early prototype releases - no longer tracked.