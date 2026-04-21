# TESSERA

AI Security Scanner for Compound Attack Chain Detection

**Version:** 1.0.4  
**Date:** April 2026

## What

TESSERA detects compound attack chains in AI/Agent systems. It uses two detection approaches:

1. **CFPE Rules** - Rule-based detection of known vulnerability patterns
2. **GNN Scanner** - ML-based detection using Graph Neural Networks (82.9% F1)

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
from tessera.rdt.gnn_scanner import GNNScanner

scanner = GNNScanner("data/best_model_v2.pt")
result = scanner.scan_topology(topology)

print(f"Vulnerable: {result['vulnerable']}")
print(f"Confidence: {result['confidence']:.0%}")
print(f"Severity: {result['severity']}")
```

## Architecture

```
src/tessera/
├── core/                    # Domain logic
│   ├── topology/           # Graph models
│   ├── detection/          # CFPE rules
│   └── findings/           # Finding models
├── rdt/                    # ML scanner
│   ├── gnn_scanner.py       # GNN-based scanner
│   ├── model.py            # RDT model
│   └── recurrent_block.py   # Core architecture
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

## Results

| Detector | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| CFPE Rules | 20% | 84% | 32% |
| **GNN Scanner** | **77%** | **90%** | **83%** |

## License

MIT

## GitHub

https://github.com/Devaretanmay/TESSERA