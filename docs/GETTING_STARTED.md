# TESSERA - Getting Started

Fast, automated AI security testing for modern AI systems.

## Installation

```bash
pip install tessera-ai
```

Or from source:

```bash
git clone https://github.com/tessera-ai/tessera.git
cd tessera
pip install -e .
```

## Quick Start

### 1. Define your AI system topology

Create a `topology.yaml` file:

```yaml
system: "my_ai_agent"
version: "1.0"

nodes:
  - id: intake_llm
    type: model
    provider: openai
    model: gpt-4o
    trust_boundary: user_controlled

  - id: product_rag
    type: rag_corpus
    backend: pinecone
    trust_boundary: partially_trusted

  - id: crm_tool
    type: tool
    trust_boundary: internal_trusted

edges:
  - from: intake_llm
    to: product_rag
    flow: retrieval
    trust_level: untrusted

  - from: intake_llm  
    to: crm_tool
    flow: tool_call
    trust_level: internal
```

### 2. Run a security scan

```bash
# Validate topology
tessera topology --config topology.yaml --validate

# Visualize attack surface
tessera topology --config topology.yaml --visualize

# Run Tier 1 scan (pre-commit, <30s)
tessera scan --config topology.yaml --tier 1
```

### 3. Export findings

```bash
# Export as SARIF (GitHub Security)
tessera findings --scan-id abc123 --format sarif --output findings.sarif
```

## Commands

| Command | Description |
|---------|-------------|
| `tessera scan` | Run security scan |
| `tessera topology` | Parse and visualize topology |
| `tessera findings` | Export scan findings |
| `tessera probes` | Manage probe registry |

## CI/CD Integration

Add to GitHub Actions:

```yaml
- name: TESSERA Scan
  run: tessera scan --config topology.yaml --tier 1
```

See `scripts/github-actions.yml` for full example.

## Backbone Options

### Local (Ollama)
```bash
tessera scan --config topology.yaml --backbone ollama
```

### OpenAI
```bash
export OPENAI_API_KEY=sk-...
tessera scan --config topology.yaml --backbone openai --model gpt-4o-mini
```

## Architecture

TESSERA models AI systems as directed graphs:

```
┌─────────┐    ┌─────────┐    ┌─────────┐
│ Model   │───▶│ RAG    │───▶│ Tool   │
└─────────┘    └─────────┘    └─────────┘
   (user)       (retrieval)      (action)
```

Threats detected:
- **Compound chain**: Multi-hop attacks spanning multiple components
- **Behavioral drift**: System behavior changes over time
- **Trust boundary bypass**: Privilege escalation via untrusted paths

## Documentation

- [CLI Reference](docs/cli.md)
- [Topology Schema](docs/topology.md)
- [API Reference](docs/api.md)

## License

Apache 2.0