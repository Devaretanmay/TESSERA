# TESSERA

AI Security Scanner for Compound Attack Chain Detection

**Version:** 2.0.0  
**Date:** April 2026

## What

TESSERA detects compound attack chains in AI/Agent systems using **CFPE Rules** - rule-based detection of known vulnerability patterns. It also supports optional **LLM-powered analysis** for semantic vulnerability detection.

The primary production surface is the public Python package and CLI. The FastAPI service is supported as a secondary deployment target for container-on-VM environments behind a reverse proxy.

## Features

- **10 CFPE Detection Patterns** - Comprehensive coverage of AI agent vulnerabilities
- **Multiple Output Formats** - Text, JSON, SARIF, HTML
- **LLM Integration** - Optional AI-powered analysis (OpenAI, Anthropic, Ollama)
- **CI/CD Ready** - GitHub Actions, pre-commit hooks
- **MCP Server** - Model Context Protocol support

## Install

```bash
pip install tessera-security
```

From source:

```bash
git clone https://github.com/Devaretanmay/TESSERA.git
cd TESSERA
pip install -e .
```

## Support Matrix

- Supported Python versions: `3.10`, `3.11`, `3.12`
- Operational default: `3.11`
- Package + CLI are the primary supported production surface
- FastAPI is a secondary production surface

## Quick Start

### CLI

```bash
# Scan a topology
tessera scan --config my_agent.yaml

# Output formats: text (default), json, sarif, html
tessera scan --config my_agent.yaml --format sarif

# List all detection rules
tessera list-rules

# Explain a specific rule
tessera explain CFPE-0001
```

### Python API

```python
from tessera import Tesseract, OutputFormat

# Simple usage
scanner = Tesseract()
result = scanner.scan("my_agent.yaml", OutputFormat.TEXT)

# JSON output
result = scanner.scan("my_agent.yaml", OutputFormat.JSON)
print(f"Found {result['summary']['total']} vulnerabilities")

# HTML report
result = scanner.scan("my_agent.yaml", OutputFormat.HTML)
with open("report.html", "w") as f:
    f.write(result)

# With LLM analysis (requires API key)
scanner.enable_llm({"provider": "openai"})
result = scanner.scan("my_agent.yaml", OutputFormat.JSON, llm_enabled=True)
```

### Programmatic Topology

```python
from tessera import Graph, Node, Edge, TrustBoundary, DataFlow, detect

graph = Graph(
    system="my_agent",
    nodes={
        "user": Node(id="user", type="user", trust_boundary=TrustBoundary.EXTERNAL),
        "llm": Node(id="llm", type="llm", trust_boundary=TrustBoundary.INTERNAL),
        "tool": Node(id="tool", type="tool", trust_boundary=TrustBoundary.INTERNAL),
    },
    edges=[
        Edge(from_node="user", to_node="llm", data_flow=DataFlow.API, trust_boundary=TrustBoundary.EXTERNAL),
        Edge(from_node="llm", to_node="tool", data_flow=DataFlow.TOOL_CALL, trust_boundary=TrustBoundary.INTERNAL),
    ]
)

findings = detect(graph)

for finding in findings:
    print(f"[{finding.severity.value.upper()}] {finding.id}: {finding.description}")
```

## Output Formats

### Text (CLI default)
```
TESSERA Security Scan
========================================
System: my_agent
Version: 1.0
Graph: 3 nodes, 2 edges
Scan time: 0.05ms

Summary:
  HIGH: 1

Findings:

1. [HIGH] CFPE-0001
   RAG to Tool execution chain detected
   Remediation:
   1. Validate RAG outputs before tool execution
   ...
```

### JSON
```json
{
  "tessera_version": "2.0.0",
  "scan": {
    "system": "my_agent",
    "version": "1.0",
    "scan_time_ms": 0.05,
    "graph": {"nodes": 3, "edges": 2}
  },
  "findings": [...],
  "summary": {"total": 1, "by_severity": {"critical": 0, "high": 1}}
}
```

### SARIF (GitHub Code Scanning)
```bash
tessera scan --config my_agent.yaml --format sarif --output results.sarif
```
Results appear in GitHub Security tab under "Code Scanning".

### HTML
Generate beautiful HTML reports:
```bash
tessera scan --config my_agent.yaml --format html --output report.html
```

## CI/CD Integration

### GitHub Actions
```yaml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev,api]"
      - run: python -m ruff check src tests
      - run: python -m pytest -q
      - run: python -m build
      - run: python -m twine check dist/*
```

### Pre-commit Hook
Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/Devaretanmay/TESSERA
    rev: v2.0.0
    hooks:
      - id: tessera-scan
```

## LLM Analysis (Optional)

TESSERA supports optional LLM-powered analysis for deeper semantic understanding:

```python
# OpenAI
scanner.enable_llm({"provider": "openai", "model": "gpt-4"})

# Anthropic
scanner.enable_llm({"provider": "anthropic", "model": "claude-3-opus"})

# Ollama (local)
scanner.enable_llm({"provider": "ollama", "model": "llama2"})
```

Set environment variables:
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

## CFPE Patterns (10 rules)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| CFPE-0001 | RAG to Tool | HIGH | LLM → RAG → Tool chain |
| CFPE-0002 | Memory Poisoning | CRITICAL | Write to persistent memory |
| CFPE-0003 | External to Database | HIGH | Untrusted → database |
| CFPE-0004 | Trust Boundary Bypass | HIGH | Cross-boundary untrusted flow |
| CFPE-0005 | Multi-hop Attack Chain | HIGH | 3+ edge attack path |
| CFPE-0006 | Tool to Tool Chaining | MEDIUM | Tool calls tool |
| CFPE-0007 | Sensitive Data Exfiltration | CRITICAL | LLM → external service |
| CFPE-0008 | RAG Context Injection | HIGH | User → RAG injection |
| CFPE-0009 | MCP Config Attack | HIGH | Malicious MCP server |
| CFPE-0010 | Agent Skill Injection | HIGH | SKILL.md compromise |

## Node Types

- `user` - Human input source
- `llm` / `model` - Language model
- `api` - API gateway
- `tool` - External tool/service
- `database` - Database
- `memory_store` - Persistent memory
- `rag_corpus` - Knowledge base (RAG)
- `external_service` - External API/service
- `mcp_server` - MCP server
- `skill` - Agent skill definition

## Trust Boundaries

```
external → user_controlled → partially_trusted → internal → privileged
```

## Architecture

```
src/tessera/
├── core/                      # Domain logic
│   ├── topology/            # Graph models (Graph, Node, Edge)
│   ├── detection/            # CFPE rules (10 patterns)
│   └── findings/             # Finding models
├── engine/                   # Scanner engine (Tesseract)
├── infra/
│   ├── output/              # Formatters (JSON, SARIF, Text, HTML)
│   ├── llm/                 # LLM providers (OpenAI, Anthropic, Ollama)
│   └── mcp/                 # MCP server
└── interfaces/
    └── cli/                  # CLI commands
```

## Production Docs

- [Deployment Guide](docs/DEPLOYMENT.md)
- [Environment Reference](docs/ENVIRONMENT.md)
- [Release Playbook](docs/RELEASE_PLAYBOOK.md)
- [Support Matrix](docs/SUPPORT_MATRIX.md)
- [Incident Runbook](docs/INCIDENT_RUNBOOK.md)
- [Security Policy](SECURITY.md)

## Testing

Run examples:

```bash
# All examples
tessera scan --config examples/*.yaml

# Specific example
tessera scan --config examples/complex_agent.yaml --format json
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for LLM analysis |
| `ANTHROPIC_API_KEY` | Anthropic API key for LLM analysis |

## License

MIT

## GitHub

https://github.com/Devaretanmay/TESSERA
