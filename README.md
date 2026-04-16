# TESSERA - Temporal, Emergent, Swarm-based Security & Evaluation for Resilience of AI

**Version:** 1.0.0  
**Date:** April 2026

---

## The Invariant: What Makes TESSERA Different

TESSERA catches attacks that per-hop scanners miss. Here's the proof:

```python
from tessera.classifier.rule_based import ChainDetector

detector = ChainDetector()

# Each hop individually scores below 0.5 (would NOT trigger alone)
per_hop_scores = [0.35, 0.40]

# But together they form a compound chain:
# Hop 1: instruction_override (RAG injection)
# Hop 2: tool_parameter_manipulation (tool misuse)
per_hop_indicators = [
    ["instruction_override"],
    ["tool_parameter_manipulation"],
]

is_compound, pattern, confidence, cfpe_id = detector.detect_chain(
    ["rag_corpus", "tool"],
    per_hop_scores,
    per_hop_indicators,
)

print(f"Chain detected: {is_compound}")  # True
print(f"Pattern: {pattern}")               # rag_to_tool
print(f"Confidence: {confidence}")        # 0.51
print(f"CFPE ID: {cfpe_id}")             # CFPE-0001
```

**This is the product.** Atomic scanners check each hop in isolation and see nothing suspicious. TESSERA sees the chain.

---

## Executive Summary

TESSERA is a behavioral security testing and continuous resilience platform for AI systems. It transforms three major open-source AI red-teaming repositories (NVIDIA's garak, Microsoft's PyRIT, and Confident AI's DeepTeam) into a unified system that addresses their shared architectural ceiling: **atomic probe-response scanners cannot detect compound behavioral failures that emerge across multi-component AI pipelines**.

TESSERA models AI systems as topology graphs, deploys cooperative synthetic agent swarms to generate adversarial scenarios that static libraries cannot anticipate, detects compound failure chains that span multiple hops, and operates both as a pre-deployment scanner and a live production behavioral monitor.

This is the leap from signature-based antivirus to modern behavioral EDR — a qualitative shift in what can be caught.

---

## The Problem: Existing Tools Have an Architectural Ceiling

### garak (NVIDIA)
- **Atomic endpoint assumption**: Every probe targets a single model endpoint. The architecture has no concept of a system — a chatbot backed by a RAG pipeline, tool-calling LLM, memory store, and external API calls.
- **Static probe library**: Detects known failure modes. A fine-tuned model patched against all known DAN variants will pass while remaining exploitable via novel compositions.
- **CI/CD impractical**: Full scans take minutes to hours. No tiered scanning model.
- **No temporal tracking**: Each scan is a fresh snapshot with no memory of previous runs.

### PyRIT (Microsoft)
- **Notebook-first interface**: An architectural anti-pattern. Optimized for researcher exploration, not developer integration.
- **Azure lock-in**: Default targets, memory backends, and deployment instructions are Azure-native.
- **No system topology**: Targets individual model endpoints only.

### DeepTeam (Confident AI)
- **Cloud dependency**: Risk management and production monitoring require the paid platform.
- **Classifier-based evaluation**: LLM-as-a-Judge susceptible to adversarial influence.
- **No topology awareness**: Same single-LLM ceiling as others.

---

## TESSERA vs. The Competition

| Capability | garak | PyRIT | DeepTeam | **TESSERA** |
|------------|------|------|---------|-------------|
| Atomic detection | ✅ | ✅ | ✅ | ✅ |
| Compound chain detection | ❌ | ❌ | ❌ | ✅ |
| Topology-based scanning | ❌ | ❌ | ❌ | ✅ |
| CI/CD tiered scans | ❌ | ❌ | ❌ | ✅ |
| Behavioral drift monitoring | ❌ | ❌ | ✅ | ✅ |
| CFPE patterns | ❌ | ❌ | ❌ | 13 |
| Open-source only | ✅ | ✅ | ❌ | ✅ |

### What TESSERA Adds

1. **Compound Failure Detection via GNN Chain Classifier** - No existing tool can detect failures that only manifest across multiple component hops. This is a class of vulnerability invisible to atomic probe scanners.

2. **Cooperative Swarm Probe Generation** - Stateful agents that share discoveries and compose attack vectors cooperatively discover novel attack paths that static probe libraries cannot.

3. **Topology-Aware Test Targeting** - Test scope is determined by the system graph, not by a model name. Indirect injection paths (user → RAG → tool → privilege escalation) are first-class test cases.

4. **Behavioral Drift Monitoring** - Continuous fingerprinting against a verified baseline. Catches post-deployment failures invisible to pre-deployment scanning.

5. **Tiered CI/CD Scan Model** - Resolves CI/CD impracticality by separating fast gate scans from comprehensive audits.

---

## Architecture

```
[Developer/CI Trigger]
      │
      ▼
[tessera.gate] ──────► Tier 1 (<30s), Tier 2 (<5min), Tier 3 (nightly)
      │
      ▼
[tessera.topology] ──► Parses system YAML, builds topology graph
      │
      ▼
[tessera.swarm] ──────► Deploys N synthetic agents (cooperative attack protocol)
      │
      ▼
[tessera.classifier] ─► Stage 1: per-hop scoring, Stage 2: GNN chain detection
      │
      ▼
[tessera.fingerprint] ─► Behavioral drift comparison
      │
      ▼
[tessera.api] ────────► Structured findings → SIEM / Dashboard
```

### Topology Definition

```yaml
system: "customer_support_agent"
nodes:
  - id: intake_llm
    type: llm
    model: gpt-4o
    trust_boundary: user_controlled
  - id: product_rag
    type: rag_corpus
    trust_boundary: partially_trusted
  - id: crm_tool
    type: tool
    trust_boundary: internal_trusted
edges:
  - from: intake_llm
    to: product_rag
    flow: retrieval
  - from: intake_llm
    to: crm_tool
    flow: tool_call
```

---

## Install

```bash
pip install tessera-security
```

Or for development:

```bash
git clone https://github.com/your-repo/tessera.git
cd tessera
pip install -e .
```

---

## Quick Start

```bash
# Validate topology
tessera topology --config examples/customer_support_agent.yaml --validate

# Run scan (Tier 1 - fast gate, <30s)
tessera scan --config examples/customer_support_agent.yaml --tier 1

# Run Tier 2 (full scan, <5min)
tessera scan --config examples/customer_support_agent.yaml --tier 2

# Run with real target
tessera scan --config topology.yaml --target-provider openai --target-model gpt-4

# Run swarm probes
tessera swarm --topology-file topology.yaml --iterations 10

# Detect behavioral drift
tessera fingerprint --calibrate baseline_queries.txt
tessera fingerprint --detect new_responses.txt --baseline baseline.json
```

---

## CFPE: Compound Failure Pattern Encyclopedia

TESSERA maintains a registry of compound failure patterns. Current patterns:

| CFPE ID | Pattern | Description |
|----------|---------|------------|
| CFPE-0001 | rag_to_tool | RAG injection → tool misuse |
| CFPE-0002 | memory_poisoning | Memory corruption chain |
| CFPE-0003 | tool_chain_escalation | Sequential tool privilege escalation |
| CFPE-0004 | trust_boundary_bypass | Cross-trust-boundary attack |
| CFPE-0005 | indirect_injection | RAG-seeded prompt injection |
| CFPE-0006 | tool_parameter_manipulation | Tool argument injection |
| CFPE-0007 | multi_model_exfiltration | Cross-model data leak |
| CFPE-0008 | agency_escalation | Excessive agency exploitation |
| CFPE-0009 | privilege_escalation_chain | Multi-hop privilege escalation |
| CFPE-0010 | data_exfiltration_chain | Data extraction via chain |
| CFPE-0011 | multi_agent_trust_propagation | Same-tier agent trust propagation |
| CFPE-0012 | multi_tool_fanout_poisoning | Parallel tool fan-out poisoning |
| CFPE-0013 | code_exec_chain | LLM → code execution → side effects |

---

## Benchmark Results

**TESSERA vs. Garak on 20 Real-World Topologies:**

| Metric | TESSERA | Garak |
|--------|--------|------|
| Topologies Scanned | 20 | 1 (limited) |
| Detection Rate | 19/20 (95%) | N/A |
| Focus | Compound chains | Atomic vulnerabilities |

**Note:** Garak ran 127 DAN probe attempts across the same topologies and did not detect topology-level compound failures in any of them.

Full benchmark report: `BENCHMARK.md`

---

## Repositories That Informed TESSERA

- **garak** (NVIDIA/garak) - Primary probe architecture, extensive probe library
- **PyRIT** (microsoft/PyRIT) - Memory and Converter abstractions
- **DeepTeam** (confident-ai/deepteam) - Vulnerability taxonomy, multi-turn attacks

---

## Future Evolution

### Near-term (6-12 months)
The compound failure taxonomy will be the primary development surface. CFPE patterns will be community-contributed.

### Medium-term (12-24 months)
Behavioral fingerprint engine will benefit from a network effect. Teams sharing anonymized baseline distributions will converge on industry-wide behavioral norms.

### Long-term (24-48 months)
Regulatory pressure for continuous behavioral certification will intensify. TESSERA's NIST AI RMF and EU AI Act mappings position it as the technical substrate for compliance attestation.

---

## Weakness Analysis: What Existing Tools Miss

### garak - Confirmed Gaps (from public GitHub issues)
- **No token cost visibility**: GitHub Issue #1532 (Dec 2025) confirms no built-in token tracking
- **CI/CD impractical**: Confirmed by user complaints — hours-long scans
- **No compound failure detection**: Architecture has no graph model
- **atkgem is "Prototype, mostly stateless"**: Uses GPT-2 fine-tuned, supports only one target

### PyRIT - Architectural Anti-Patterns
- **Notebook-first**: Own docs state "most new logic should not be notebooks"
- **Memory is write-only**: Records past interactions but no behavioral analysis layer
- **Azure lock-in**: Default targets, backends assume Azure OpenAI

### DeepTeam - Platform Dependencies
- **Cloud required**: Risk management features need paid platform
- **No topology awareness**: Single LLM target ceiling
- **LLM-as-a-Judge risk**: Evaluation substrate shares model with attack substrate

---

## Core Components

### 1. Topology Modeler (tessera.topology)
Accepts system definition in YAML/JSON. Nodes are model endpoints, tools, memory, RAG corpora. Edges are data flows with trust levels.

### 2. Swarm Probe Engine (tessera.swarm)
Deploys N synthetic agents against topology graph:
- **Roles**: injector, escalation tracer, trust boundary probe, exfiltration scout, behavioral fuzzer
- **Cooperative protocol**: Agents share discoveries via communication bus
- **Adaptive generation**: Generates attacks from canonical primitives, not static library

### 3. Compound Failure Classifier (tessera.classifier)
Two-stage pipeline:
- **Stage 1**: Per-hop embedding classifier (fast, runs at inference speed)
- **Stage 2**: GNN chain detector (classifies multi-hop compound failures)
- **Independence**: Evaluation substrate independent of attack substrate

### 4. Behavioral Fingerprint Engine (tessera.fingerprint)
- Establishes verified-clean baseline
- Uses Maximum Mean Discrepancy (MMD) for drift detection
- Catches: model updates, corpus poisoning, gradual jailbreak, config changes

### 5. Findings API (tessera.api)
Structured output with OWASP/NIST/EU AI Act mapping. SARIF output for GitHub Code Scanning.

---

## Data Flow

```
Inbound: Topology YAML → live interaction traces → CI trigger
         │
State: Topology graph → behavioral baseline → findings log
         │
Outbound: REST API → webhook → SIEM
```

---

## Infrastructure

- **Package**: `pip install tessera-ai`
- **Backbone LLM**: Configurable (default: local Ollama/Llama 3)
- **State**: SQLite (default), Postgres (production), Redis (swarm)
- **Deployment**: Docker Compose, Helm for Kubernetes

---

## Risks and Tradeoffs

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| GNN requires training data | High | Medium | Pre-trained on AgentHarm + synthetic corpus |
| Topology drift | Medium | High | Auto-discovery from OpenAPI/LangGraph |
| Swarm cost | Medium | Medium | Cost estimates shown upfront |
| False positives | High | Low | Sliding window confirmation |

---

## The Historical Parallel

Early antivirus: signature databases → blind to novel behavior
Modern EDR: behavioral monitoring → catches what signatures miss

**AI security is at the signature database moment. TESSERA is the behavioral EDR.**

---

## License

MIT

---

## Contributing

TESSERA is an open-source project. Contributions welcome.

1. Fork the repo
2. Create a feature branch
3. Add tests for new CFPE patterns
4. Submit a Pull Request