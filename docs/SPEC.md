# TESSERA - Product Requirements Document

**Version:** 1.0  
**Status:** Draft  
**Date:** April 14, 2026  
**Team:** Solo/2-3 Engineers  
**Timeline:** 12 Months to v1  

---

## 1. Overview

### 1.1 Product Vision

TESSERA (Temporal, Emergent, Swarm-based Security & Evaluation for Resilience of AI) is a behavioral security testing and continuous resilience platform for AI systems. It models AI systems as topology graphs, deploys cooperative synthetic agent swarms to generate adversarial scenarios, detects compound failure chains across multi-hop pipelines, and monitors behavioral drift in production.

### 1.2 Problem Statement

Current AI security tools (garak, PyRIT, DeepTeam) are atomic endpoint scanners that:

- Target single model endpoints only - cannot detect compound failures across multi-component pipelines
- Run static probe libraries - cannot adapt to novel attack patterns
- Produce one-time reports - cannot monitor behavioral drift
- Lack CI/CD practicality - scan times incompatible with developer workflows

### 1.3 Solution Summary

TESSERA addresses these gaps through:

1. **Topology Graph Modeling** - Models AI systems as directed graphs of components
2. **Cooperative Swarm Probes** - Stateful agents that cooperate to find attack chains
3. **Compound Failure Classification** - GNN-based chain detection
4. **Behavioral Drift Monitoring** - Continuous fingerprinting against baselines
5. **Tiered CI/CD Gates** - Fast gate scans + comprehensive audits
6. **Structured Findings API** - SIEM-integrable output
7. **Probe Registry** - Extensible vulnerability taxonomy

---

## 2. Technical Architecture

### 2.1 System Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                      TESSERA Platform                     │
├─────────────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐ │
│  │  Gate   │───▶│Topology │───▶│ Swarm   │───▶│Classifier│ │
│  │ (CI/CD) │    │ Modeler │    │  Probe  │    │         │ │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘ │
│       │                                        │         │
│       ▼                                        ▼         │
│  ┌─────────┐    ┌─────────────────────────────────────┐ │
│  │ Finger- │◀───│         Findings API                │ │
│  │print   │    │  (REST + Webhook + SIEM export)      │ │
│  └─────────┘    └─────────────────────────────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────────────┘

External Interfaces:
- CI/CD Pipeline (GitHub Actions, GitLab CI)
- LLM Providers (OpenAI, Anthropic, Bedrock, Ollama)
- Vector Stores (Pinecone, Weaviate, Chroma)
- SIEM Systems (Splunk, Datadog, Elasticsearch)
```

### 2.2 Core Components

| Component | Responsibility | Priority |
|-----------|----------------|----------|
| `tessera.gate` | Tiered CI/CD scan orchestration | P0 |
| `tessera.topology` | System graph modeling | P0 |
| `tessera.swarm` | Cooperative adversarial agents | P1 |
| `tessera.classifier` | Compound failure detection (GNN) | P1 |
| `tessera.fingerprint` | Behavioral drift monitoring | P1 |
| `tessera.api` | Findings export API | P0 |
| `tessera.probes` | Probe registry | P1 |

### 2.3 Data Flow

```
1. Developer/CI triggers scan
       │
       ▼
2. tessera.gate routes to tier (1/2/3)
       │
       ▼
3. tessera.topology parses YAML → builds graph
       │
       ▼
4. tessera.swarm deploys N agents (cooperative protocol)
       │         │
       │         ▼
       │    Agent shares findings to bus
       │         │
       ▼         ▼
5. tessera.classifier scores per-hop + chains
       │
       ▼
6. tessera.fingerprint compares drift
       │
       ▼
7. tessera.api outputs structured findings
       │
       ▼
8. SIEM / Dashboard / Developer receives
```

---

## 3. Data Models

### 3.1 Topology Definition (YAML)

```yaml
# tessera.topology.yaml
system: "customer_support_agent"
version: "1.0"

nodes:
  - id: intake_llm
    type: model
    provider: openai
    model: gpt-4o
    trust_boundary: user_controlled
    config:
      temperature: 0.3
      max_tokens: 2048

  - id: product_rag
    type: rag_corpus
    backend: pinecone
    index: customer-support-kb
    trust_boundary: partially_trusted

  - id: crm_tool
    type: tool
    schema_url: https://internal.tools/crm.json
    trust_boundary: internal_trusted
    capabilities:
      - read_customer
      - update_ticket

  - id: memory_store
    type: memory
    backend: redis
    ttl: 3600
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

  - from: intake_llm
    to: memory_store
    flow: read_write
    trust_level: internal
```

### 3.2 Probe Definition

```yaml
# probe example
id: compound_injection_rag_tool
name: "Compound RAG→Tool Injection"
version: "1.0"

failure_category: compound_chain
severity: critical

taxonomy_tags:
  - owasp: LLM01
  - owasp: LLM06
  - nist_ai_rmf: PR.AIP-2

topology_requirements:
  min_nodes: 2
  required_types: [model, rag_corpus, tool]
  edge_flows: [retrieval, tool_call]

attack_primitive: injection
escalation_path: [rag_poisoning, tool_privilege_escalation]

detection:
  per_hop_indicators:
    - context_containment
    - instruction_override
    - tool_parameter_manipulation
  chain_patterns:
    - retrieval_leads_to_tool
```

### 3.3 Finding Definition

```json
{
  "finding_id": "uuid",
  "scan_id": "uuid",
  "timestamp": "ISO8601",
  
  "severity": "critical|high|medium|low|info",
  "failure_type": "compound_chain|atomic_injection|behavioral_drift|trust_boundary_bypass",
  
  "topology_path": ["intake_llm", "product_rag", "crm_tool"],
  "attack_trace": [
    {
      "node": "product_rag",
      "action": "retrieval",
      "prompt": "...",
      "response": "...",
      "suspicion_score": 0.85,
      "indicators": ["instruction_override", "context_containment"]
    }
  ],
  
  "evidence": {
    "injected_content": "...",
    "tool_invocation": "...",
    "privilege_escalation": true
  },
  
  "remediation": {
    "input_validation": ["instruction_hierarchy_enforcement"],
    "output_filtering": ["context_isolation"],
    "architecture": ["trust_boundary_enforcement"]
  },
  
  "confidence": 0.92,
  "cve_refs": [],
  "owasp_mapping": ["LLM01", "LLM06"]
}
```

---

## 4. Component Specifications

### 4.1 CI/CD Gate (tessera.gate)

**Responsibility:** Orchestrate tiered scan execution

**Tiers:**

| Tier | Trigger | Scope | Time Budget | Blocking |
|------|---------|-------|--------------|----------|
| Tier 1 | Pre-commit | Top-20 critical probes | < 30s | Binary pass/fail |
| Tier 2 | Pre-deploy | Full topology scan | < 5m | Severity threshold |
| Tier 3 | Nightly/Weekly | Swarm + drift | < 60m | Dashboard only |

**Flow:**

```
gate.receive(trigger, tier) → 
  gate.select_probes(tier) →
  gate.execute_async() →
  gate.evaluate() →
  gate.decide_blocking() →
  gate.emit(findings)
```

**CLI Interface:**

```bash
# Tier 1: Pre-commit
tessera gate --tier 1 --config topology.yaml

# Tier 2: Pre-deploy  
tessera gate --tier 2 --config topology.yaml --severity threshold=high

# Tier 3: Nightly
tessera gate --tier 3 --config topology.yaml --drift-baseline baseline.json
```

### 4.2 Topology Modeler (tessera.topology)

**Responsibility:** Parse topology YAML, build directed graph, validate

**Data Structures:**

```python
class TopologyNode:
    id: str
    type: Literal["model", "rag_corpus", "tool", "memory", "api"]
    provider: str
    trust_boundary: Literal["trusted", "partially_trusted", "untrusted"]
    config: dict

class TopologyEdge:
    from_node: str
    to_node: str
    flow: Literal["retrieval", "tool_call", "read_write", "api"]
    trust_level: Literal["trusted", "untrusted"]

class TopologyGraph:
    nodes: dict[str, TopologyNode]
    edges: list[TopologyEdge]
    
    def paths_between(self, start: str, end: str) → list[list[str]]:
    def trust_chains(self) → list[TrustChain]:
    def attack_surface(self) → list[AttackSurface]:
```

**Validation Rules:**

- All referenced nodes must exist
- No cycles in trust boundaries (warn)
- Required capabilities for tool nodes
- RAG nodes need backend config

### 4.3 Swarm Probe Engine (tessera.swarm)

**Responsibility:** Deploy cooperative adversarial agents

**Architecture:**

```
┌────────────────────────────────────────────┐
│          Swarm Coordinator                   │
│  (Orchestrates N agents, manages bus)        │
└────────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ Agent 1 │ │ Agent 2 │ │ Agent 3 │
   │Injector │ │Escalator│ │  Scout  │
   └─────────┘ └─────────┘ └─────────┘
        │           │           │
        └───────────┼───────────┘
                    │
            ┌───────▼───────┐
            │ Shared Bus    │
            │ (Redis Pub/Sub)│
            └───────────────┘
```

**Agent Roles:**

| Role | Purpose | Primitive Set |
|------|---------|---------------|
| `injector` | Seed malicious content | injection, encoding |
| `escalator` | Propagate & escalate | context_manipulation, tool_ abuse |
| `scout` | Explore boundaries | trust_boundary_probe |
| `fuzzer` | Find edge cases | mutation, boundary_test |

**Communication Protocol:**

```python
class AgentMessage:
    type: Literal["discovery", "request", "response", "alert"]
    from_agent: str
    payload: dict
    priority: int
    
# Example: Injector finds RAG vulnerability
bus.publish(AgentMessage(
    type="discovery",
    from_agent="injector-1",
    payload={
        "node": "product_rag",
        "weakness": "retrieval_injection",
        "vector": "embedded_instruction"
    },
    priority=10  # High priority triggers escalation
))
```

**Backbone LLM Configuration:**

```python
class SwarmConfig:
    agent_count: int = 5  # Default
    backbone: str = "ollama/llama3:8b"  # Default local
    max_iterations: int = 50
    timeout_per_agent: int = 300
    
    # Override for enterprise
    backbone_api: str = None  # OpenAI compatible
    backbone_model: str = None
    cost_estimate: float = None  # Displayed before run
```

### 4.4 Compound Failure Classifier (tessera.classifier)

**Responsibility:** Detect compound failure chains

**Two-Stage Pipeline:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Stage 1: Per-Hop Detection                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Local Classifier (Embedding-based)                  │   │
│  │ Input: node + prompt + response                    │   │
│  │ Output: suspicion_score (0.0-1.0)                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Stage 2: Chain Detection                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ GNN Classifier                                     │   │
│  │ Input: graph of suspicion scores                    │   │
│  │ Output: compound_failure_label                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Stage 1: Local Indicators**

| Indicator | Description |
|-----------|-------------|
| `instruction_override` | Response ignores explicit instructions |
| `context_containment` | Response contains injected context |
| `tool_parameter_manipulation` | Tool call contains attacker-controlled params |
| `privilege_escalation` | Action exceeds authorized scope |
| `data_exfiltration` | Response leaks sensitive data |

**Stage 2: Chain Patterns**

```python
# Example chain patterns
CHAIN_PATTERNS = {
    "rag_to_tool": {
        "description": "RAG injection → tool misuse",
        "node_types": ["rag_corpus", "tool"],
        "edge_flows": ["retrieval", "tool_call"],
        "indicators": ["instruction_override", "tool_parameter_manipulation"]
    },
    "memory_to_model": {
        "description": "Memory poisoning → model behavior change",
        "node_types": ["memory", "model"],
        "edge_flows": ["read_write"],
        "indicators": ["behavioral_shift"]
    }
}
```

**GNN Architecture (Cold-Start Strategy):**

```python
class CompoundClassifierGNNColdStart:
    """
    Phase 1: Use heuristic rules instead of trained GNN
    """
    
    # Rule-based composition detection
    COMPOSITION_RULES = [
        # Rule: Retrieval followed by tool call = potential chain
        lambda path: "retrieval" in path and "tool_call" in path,
        # Rule: Untrusted edge in chain = escalation risk
        lambda edge: edge.trust_level == "untrusted",
    ]
    
    """
    Phase 2: Once trained data exists, replace with:
    
    class CompoundClassifierGNN:
        def __init__(self):
            self.model = GraphConvNetwork(
                node_features=64,
                hidden_dims=128,
                num_classes=4,  # safe, suspicious, likely_compound, compound
            )
    """

# Initial training data strategy (AgentHarm benchmark)
INITIAL_TRAINING_DATA = [
    "AgentHarm benchmark (110 malicious agentic tasks)",
    "Synthetic compound failures (generated)",
    "garak probe traces converted to single-hop",
]
```

### 4.5 Behavioral Fingerprint Engine (tessera.fingerprint)

**Responsibility:** Detect behavioral drift in production

**Calibration Phase:**

```python
class FingerprintCalibration:
    """
    Establish baseline during initial calibration
    """
    
    SAMPLE_SIZE = 1000  # Stratified samples
    
    CATEGORIES = [
        "benign_standard",      # Normal user queries
        "benign_edge",         # Edge cases, boundary
        "adversarial_known",  # Known attack patterns
    ]
    
    def calibrate(self, system, samples) → BehavioralFingerprint:
        embeddings = [self.embed(response) for response in samples]
        return BehavioralFingerprint(
            mean_embedding=np.mean(embeddings, axis=0),
            distribution={
                "benign_standard": np.percentile(embeddings, [5, 95]),
                "benign_edge": np.percentile(embeddings, [10, 90]),
            }
        )
```

**Drift Detection:**

```python
class DriftDetector:
    """
    Detect distributional shift using Maximum Mean Discrepancy
    """
    
    def detect_drift(self, current_responses, baseline) → DriftReport:
        current_embeddings = [self.embed(r) for r in current_responses]
        mmd_score = self.compute_mmd(current_embeddings, baseline)
        
        return DriftReport(
            mmd_score=mmd_score,
            threshold=self.drift_threshold,
            is_drift=mmd_score > self.drift_threshold,
            recommended_action="alert" if is_drift else "none"
        )
    
    DRIFT_THRESHOLD = 0.15  # Tunable
```

### 4.6 Findings API (tessera.api)

**Responsibility:** Export structured findings

**REST Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scans` | POST | Create new scan |
| `/api/v1/scans/{id}` | GET | Get scan status |
| `/api/v1/scans/{id}/findings` | GET | List findings |
| `/api/v1/scans/{id}/findings/{fid}` | GET | Get finding detail |
| `/api/v1/fingerprints` | GET | List baselines |
| `/api/v1/fingerprints/{id}` | GET | Get fingerprint |

**Webhook Events:**

```python
class WebhookPayload:
    event: Literal["scan.completed", "finding.created", "drift.detected"]
    scan_id: str
    timestamp: str
    payload: Finding | DriftReport
```

**Export Formats:**

- JSON (structured)
- JSONL (line-delimited)
- SARIF (GitHub Code Scanning)
- CEF (Common Event Format for SIEM)

### 4.7 Probe Registry (tessera.probes)

**Responsibility:** Maintain probe library + taxonomy

**Probe Import:**

```python
# Support garak probe format
class GarakProbeImporter:
    def import_probe(self, garak_probe_path) → TESSERAProbe:
        # Convert garak probe → TESSERA format
        # Single-hop probes become chain of 1
        pass
    
    def import_probes(self, directory) → list[TESSERAProbe]:
        pass
```

**Taxonomy Mapping:**

```python
TAXONOMY_MAPPING = {
    "owasp_llm_top10_2025": {
        "LLM01": "prompt_injection",
        "LLM02": "sensitive_info_disclosure",
        "LLM03": "supply_chain",
        "LLM04": "data_model_poisoning",
        "LLM05": "improper_output_handling",
        "LLM06": "excessive_agency",
        "LLM07": "system_prompt_leakage",
        "LLM08": "vector_embedding_weakness",
        "LLM09": "misinformation",
        "LLM10": "unbounded_consumption",
    },
    "nist_ai_rmf": ["PR.AIP-1", "PR.AIP-2", "PR.AIP-3"],
    "eu_ai_act": ["Article 5", "Article 50"],
}
```

---

## 5. Technical Stack

### 5.1 Core Technologies

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Language | Python 3.11+ | Ecosystem + LLM compatibility |
| Async | asyncio + celery | Concurrent agent orchestration |
| Graph | networkx | Topology modeling |
| ML | PyTorch + torch-geometric | GNN classifier |
| Vector | sentence-transformers | Embedding-based detection |
| API | FastAPI | REST API + streaming |
| DB | SQLite (dev) / Postgres (prod) | Scan results + findings |
| Cache | Redis | Swarm communication bus |
| CLI | typer | CLI with type safety |

### 5.2 LLM Integration

```python
# Pluggable backbone
class BackboneAdapter(Protocol):
    async def generate(self, prompt: str, **kwargs) -> str:
        ...

# Implementations
class OpenAIAdapter(BackboneAdapter):
    ...
    
class OllamaAdapter(BackboneAdapter):
    ...
    
class AnthropicAdapter(BackboneAdapter):
    ...
```

### 5.3 Dependencies (Key)

```txt
# Core
fastapi>=0.109.0
uvicorn>=0.27.0
pydantic>=2.5.0
typer>=0.12.0

# Graph & ML
torch>=2.2.0
torch-geometric>=2.5.0
networkx>=3.2.0
sentence-transformers>=2.4.0

# Data
sqlalchemy>=2.0.0
redis>=5.0.0
asyncpg>=0.29.0

# LLM
openai>=1.12.0
anthropic>=0.18.0
ollama>=0.1.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0
httpx>=0.26.0
```

---

## 6. CLI Interface

### 6.1 Command Structure

```bash
# Scanning
tessera scan --config topology.yaml [--tier 1|2|3]
tessera scan --target http://localhost:8000/v1/chat

# Topology
tessera topology validate topology.yaml
tessera topology visualize topology.yaml
tessera topology attack-surface topology.yaml

# Probes
tessera probes list [--category LLM01]
tessera probes add probe.yaml
tessera probes import-garak /path/to/garak

# Findings
tessera findings list --scan-id <id>
tessera findings export --format sarif --output findings.sarif
tessera findings webhook --url https://.../

# Fingerprint
tessera fingerprint calibrate topology.yaml --sample-queries queries.txt
tessera fingerprint detect-drift --baseline baseline.json

# Gate (CI/CD)
tessera gate pre-commit
tessera gate pre-deploy
tessera gate nightly
```

### 6.2 Configuration Files

```bash
# ~/.tessera/config.yaml
api:
  host: 0.0.0.0
  port: 8000
  
backbone:
  provider: openai  # or ollama, anthropic
  model: gpt-4o-mini
  api_key: ${OPENAI_API_KEY}

gate:
  tier1_timeout: 30
  tier2_timeout: 300
  tier3_timeout: 3600

redis:
  host: localhost
  port: 6379
```

---

## 7. Milestones

### 7.1 Phase 1: Foundation (Months 1-4)

| Week | Deliverable |
|------|-------------|
| 1-2 | Project setup, CI/CD |
| 3-4 | Core data models |
| 5-6 | Topology Modeler |
| 7-8 | CI/CD Gate - Tier 1/2 |
| 9-10 | Findings API |
| 11-12 | Basic Probe Registry |
| 13-16 | Basic CLI + tests |

**Exit Criteria:**

- `tessera gate --tier 1` completes in <30s
- Scan results via API
- Working basic CLI

### 7.2 Phase 2: Core Innovation (Months 5-8)

| Week | Deliverable |
|------|-------------|
| 17-20 | Swarm Probe (local model) |
| 21-24 | Rule-based classifier |
| 25-28 | Fingerprint calibration |
| 29-32 | Integration tests |

**Exit Criteria:**

- Swarm generates 5+ unique attack traces
- Classifier detects chain patterns
- Baseline calibration works

### 7.3 Phase 3: Production (Months 9-12)

| Week | Deliverable |
|------|-------------|
| 33-36 | GNN training pipeline |
| 37-40 | Drift monitoring |
| 41-44 | Enterprise features |
| 45-48 | v1 release |

**Exit Criteria:**

- v1.0 release
- Documentation complete
- Docker deployment

---

## 8. Risk Mitigation

| Risk | Mitigation |
|------|------------|
| GNN cold-start | Rule-based fallback in Phase 1 |
| Topology friction | Auto-discovery from OpenAPI |
| Swarm cost | Local Ollama default |
| False positives | Confidence scoring + sliding window |

---

## 9. Acceptance Criteria

### 9.1 Functional Requirements

- [ ] Tier 1 scan completes in <30 seconds
- [ ] Tier 2 scan completes in <5 minutes
- [ ] Topology YAML parses into graph
- [ ] Findings export to JSON, SARIF, JSONL
- [ ] CLI for scan, topology, findings commands
- [ ] Probe registry with taxonomy mapping
- [ ] Docker deployment works

### 9.2 Prototype Requirements

- [ ] Swarm generates multi-hop attack traces
- [ ] Classifier detects known chain patterns
- [ ] Fingerprint calibrates baseline
- [ ] Drift detection fires on behavioral shift

### 9.3 Non-Functional Requirements

- [ ] 95% test coverage on core components
- [ ] <100ms API response time
- [ ] Memory <2GB idle
- [ ] Works offline (local models)

---

*End of PRD*