# TESSERA

AI Security Scanner for Compound Attack Chain Detection

**Version:** 1.1.0  
**Date:** April 2026

## What

TESSERA detects compound attack chains in AI/Agent systems using **CFPE Rules** - rule-based detection of known vulnerability patterns.

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

### Scan a topology

```bash
tessera scan --config my_agent.yaml
```

### Python API

```python
from tessera import detect, Graph, Node, Edge, TrustBoundary, DataFlow

# Define your agent topology
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

# Detect vulnerabilities
findings = detect(graph)

for finding in findings:
    print(f"[{finding.severity.value.upper()}] {finding.id}: {finding.description}")
```

## Testing

Run the included examples:

```bash
python -c "
import sys; sys.path.insert(0, 'src')
from tessera.core.topology.loader import Loader
from tessera import detect

loader = Loader()
graph = loader.load('examples/complex_agent.yaml')
findings = detect(graph)
print(f'Found {len(findings)} vulnerabilities')
for f in findings:
    print(f'  - {f.id}: {f.description}')
"
```

## Architecture

```
src/tessera/
├── core/                    # Domain logic
│   ├── topology/           # Graph models
│   ├── detection/          # CFPE rules
│   └── findings/           # Finding models
├── engine/                 # Pipeline
├── infra/                   # API & DB
└── interfaces/             # CLI
```

## CFPE Patterns

| ID | Pattern | Severity |
|----|---------|----------|
| CFPE-0001 | RAG to Tool | HIGH |
| CFPE-0002 | Memory Poisoning | CRITICAL |
| CFPE-0004 | Trust Boundary Bypass | HIGH |

## Node Types

- `user` - Human input
- `llm` - Language model
- `api` - API gateway
- `tool` - External tool
- `database` - Database
- `memory_store` - Memory
- `rag_corpus` - Knowledge base
- `external_service` - External service

## Trust Boundaries

`external` → `user_controlled` → `partially_trusted` → `internal` → `privileged`

## License

MIT

## GitHub

https://github.com/Devaretanmay/TESSERA