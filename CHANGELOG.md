# Changelog

All notable changes to TESSERA will be documented in this file.

## [2.0.0] - 2026-04-22

### Added
- **10 CFPE Detection Patterns** (up from 3)
  - CFPE-0007: Sensitive Data Exfiltration (CRITICAL)
  - CFPE-0008: RAG Context Injection (HIGH)
  - CFPE-0009: MCP Config Attack (HIGH)
  - CFPE-0010: Agent Skill Injection (HIGH)
- **HTML Output Formatter** - Beautiful styled HTML reports
- **LLM Integration** - Optional AI-powered semantic analysis
  - OpenAI provider (gpt-4, gpt-3.5-turbo)
  - Anthropic provider (claude-3-opus, claude-3-sonnet)
  - Ollama provider (local models)
- **Pre-commit Hook** - Local security scanning
- **MCP Server Stub** - Model Context Protocol support
- **GitHub Actions Workflow** - CI/CD integration
- **Remediation Guidance** - Every finding includes fix instructions

### Changed
- Scanner now returns structured results with severity counts
- SARIF output upgraded to v2.1.0
- All CFPE patterns include remediation guidance
- CLI rewritten with Typer for better UX

### Fixed
- Error handling for missing files
- Graceful degradation when LLM unavailable

## [1.0.0] - 2026-04-XX

### Added
- Initial release
- 3 CFPE detection patterns
- Basic CLI
- JSON output

---

## Installation

```bash
pip install tessera-security
```

## Upgrading

```bash
pip install --upgrade tessera-security
```
