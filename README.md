# TESSERA

AI Security Scanner - Compound Attack Chain Detection

**Version:** 1.0.3  
**Date:** April 2026  
**Install:** `pip install tessera-security`

## What

TESSERA detects compound attack chains in AI/Agent systems that single-hop scanners miss. Model your AI system as a topology graph and scan for CFPE (Compound Failure Pattern Exploitation) vulnerabilities.

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

## Quick Start

### Create topology file

Save as `my_agent.yaml`:

```yaml
system: "customer_support_bot"
version: "1.0.0"
nodes:
  - id: intake
    type: llm
    model: gpt-4o
    trust_boundary: user_controlled
  - id: rag_kb
    type: rag_corpus
    trust_boundary: partially_trusted
  - id: crm_tool
    type: tool
    trust_boundary: internal
edges:
  - from: intake
    to: rag_kb
    flow: retrieval
  - from: intake
    to: crm_tool
    flow: tool_call
```

### Run scan

```bash
tessera scan --config my_agent.yaml --tier 2
```

### View results

```bash
tessera findings
```

## Commands

| Command | Description |
|---------|-------------|
| `tessera scan` | Run security scan |
| `tessera topology` | Validate topology |
| `tessera findings` | View scan results |
| `tessera scans` | List scan history |
| `tessera server` | Start API server |

## Architecture

```
src/tessera/
├── core/                    # Pure domain logic
│   ├── topology/models.py   # Graph, Node, Edge schemas
│   ├── topology/loader.py   # YAML parsing
│   ├── detection/patterns.py # CFPE rules
│   └── findings/models.py   # Finding model
├── engine/
│   └── scanner.py           # Pipeline orchestration
├── infra/
│   ├── api/server.py       # FastAPI endpoints
│   └── db/repository.py    # SQLite persistence
└── interfaces/
    └── cli/main.py          # CLI entrypoint
```

## CFPE Patterns

Detects compound attack chains:

| ID | Pattern | Severity |
|----|---------|----------|
| CFPE-0001 | RAG to Tool | HIGH |
| CFPE-0002 | Memory Poisoning | CRITICAL |
| CFPE-0004 | Trust Boundary Bypass | HIGH |

## API Server

```bash
tessera server --port 8000
```

Query:

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/v1/scans \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"topology_path": "my_agent.yaml", "tier": "2"}'
```

## Trust Boundaries

- `public` - External, untrusted
- `external` - External interface
- `user_controlled` - User input
- `partially_trusted` - Shared resources
- `internal` - Internal system
- `privileged` - Admin/system

## Data Flows

- `retrieval` - RAG/knowledge retrieval
- `tool_call` - Tool execution
- `read_write` - Persistent storage
- `api` - API communication
- `inference` - LLM inference
- `signal` - Event/callback

## License

MIT

## GitHub

https://github.com/Devaretanmay/TESSERA
