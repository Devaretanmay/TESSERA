# TESSERA Roadmap: Current → Spec Goal

**Target**: Reach full spec vision (TESSERA v1.0)  
**Current State**: v0.1.0 prototype (topology + basic scan working)  
**Distance**: ~24 months from prototype to spec-complete

---

## Phase 1: Foundation (Months 1-4)
### Goal: Ship working MVP

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| Topology Modeler | Working | v1.0 | ✓ Ready |
| Local Classifier | Keywords | Enhanced | In Progress |
| Chain Detector | Rules | v1.0 | Needs work |
| Scan CLI | Tier 1 | Tier 1-2 | Build |
| Findings API | REST | Full | Build |
| Persistence | SQLite | v1.0 | ✓ Ready |

### Deliverables (Phase 1)
- [x] Topology YAML parser + validator
- [x] Scan CLI `--tier 1/2`
- [x] Findings export (JSON/SARIF/JSONL)
- [x] SQLite persistence
- [ ] Enhanced local classifier (embedding-based)
- [ ] Rule-based chain detector (3 patterns)
- [ ] Tier 2 scan (full graph)
- [ ] CI/CD gate integration

### Timeline
| Week | Deliverable |
|------|-------------|
| 1-2 | Enhanced local classifier |
| 3-4 | Tier 2 scan implementation |
| 5-6 | Findings API polish |
| 7-8 | CI/CD gate scripts |
| 9-12 | Integration tests + polish |
| 13-16 | v0.2.0 release |

### Exit Criteria
- `tessera gate --tier 1` completes in <30s
- `tessera gate --tier 2` completes in <5min
- Scan results via REST API
- Working JSON/SARIF export

---

## Phase 2: GNN Classifier (Months 5-8)
### Goal: Train compound failure detector

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| GNN Classifier | Random init | Pre-trained | Build |
| Training Data | None | 500+ samples | Create |
| Graph Features | Basic | Full | Enhance |
| Chain Patterns | 3 rules | 10+ patterns | Add |

### Training Data Strategy

```
Source 1: AgentHarm benchmark (110 tasks)
├── Already labeled malicious tasks
├── Convert to graph traces
└── ~110 samples

Source 2: Synthetic compound failures
├── RAG → Tool chains
├── Memory → Model chains  
├── Tool chain escalation
└── ~200 samples

Source 3: garak probe traces
├── Convert single-hop to multi-hop
└── ~200 samples

Total: ~500 samples for cold-start
```

### Deliverables (Phase 2)
- [ ] GNN trained on compound failure corpus
- [ ] 10+ chain pattern rules
- [ ] Per-hop scoring (embedding-based)
- [ ] Combined rule-based + GNN confidence
- [ ] Evaluation on held-out test set

### Timeline
| Week | Deliverable |
|------|-------------|
| 17-20 | Training data curation |
| 21-24 | GNN training pipeline |
| 25-28 | Chain pattern expansion |
| 29-32 | Testing + evaluation |
| 33-36 | v0.3.0 release |

### Exit Criteria
- GNN achieves >80% accuracy on test set
- Combined classifier reduces false positives by 40%
- Detects 10+ compound chain patterns

---

## Phase 3: Swarm Execution (Months 9-14)
### Goal: Cooperative agent probes

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| Swarm Engine | Stub | Full | Build |
| Agent Protocol | None | Implemented | Build |
| Backbone Adapter | Stub | Ollama+OpenAI | Build |
| Discovery Bus | None | Redis | Build |

### Architecture

```
SwarmCoordinator
├── Agent-1 (Injector)     ← Seeds attacks
├── Agent-2 (Escalator)   ← Propagates attacks  
├── Agent-3 (Scout)       ← Explores boundaries
├── Agent-4 (Fuzzer)     ← Edge cases
├── Agent-5 (Exfil)      ← Data exfiltration
└── Shared Bus (Redis)    ← Discovery sharing
```

### Agent Roles + Primitives

| Role | Purpose | Primitive Set |
|------|---------|---------------|
| Injector | Seed malicious content | injection, encoding, role_play |
| Escalator | Propagate & escalate | context_manipulation, tool_abuse |
| Scout | Explore boundaries | trust_boundary_probe |
| Fuzzer | Find edge cases | mutation, boundary_test |
| Exfil | Extract data | data_extraction, prompt_leakage |

### Communication Protocol

```python
class AgentMessage:
    type: "discovery" | "request" | "response" | "alert"
    from_agent: str
    payload: dict  # {node, weakness, vector}
    priority: int  # 1-10
    
# Example: Injector finds RAG vulnerability
bus.publish(AgentMessage(
    type="discovery",
    from_agent="injector-1",
    payload={
        "node": "product_rag",
        "weakness": "retrieval_injection", 
        "vector": "embedded_instruction"
    },
    priority=10  # High = trigger escalation
))
```

### Deliverables (Phase 3)
- [ ] Swarm coordinator (5 agents)
- [ ] Agent role definitions
- [ ] Communication bus (Redis)
- [ ] Backbone adapters (Ollama, OpenAI, Anthropic)
- [ ] Adaptive probe generation
- [ ] Cost estimation before run

### Timeline
| Week | Deliverable |
|------|-------------|
| 37-40 | Swarm coordinator |
| 41-44 | Agent protocols |
| 45-48 | Backbone adapters |
| 49-52 | Adaptive generation |
| 53-56 | Tier 3 integration |
| 57-60 | v0.4.0 release |

### Exit Criteria
- Swarm produces 5+ unique attack traces
- Agents share discoveries via bus
- Cost estimate shown before run
- Tier 3 completes in <60min

---

## Phase 4: Drift Detection (Months 15-18)
### Goal: Behavioral fingerprinting

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| Fingerprint Engine | Stub | Full | Build |
| Baseline Calibration | Stub | Working | Build |
| Drift Detection | None | MMD-based | Build |
| Alert Webhook | Stub | Full | Build |

### Architecture

```
Calibration Phase:
1. Load system topology
2. Generate stratified sample queries
   ├── Benign standard (70%)
   ├── Benign edge cases (20%)
   └── Known adversarial (10%)
3. Run queries → capture responses
4. Embed responses → distribution
5. Save baseline (JSON)

Drift Detection Phase:
1. Sample live traffic (proxy/instrumentation)
2. Embed responses  
3. Compute MMD vs baseline
4. If MMD > threshold → alert
5. Optional: webhook to SIEM
```

### MMD Implementation

```python
def compute_mmd(X, Y, kernel):
    """Maximum Mean Discrepancy"""
    X = kernel(X)
    Y = kernel(Y)
    return np.abs(X.mean() - Y.mean())

# Threshold tuning
DRIFT_THRESHOLD = 0.15  # Tunable
# < 0.15: No drift
# 0.15-0.30: Warning
# > 0.30: Alert
```

### Deliverables (Phase 4)
- [ ] Baseline calibration CLI
- [ ] Drift detection CLI
- [ ] MMD-based scoring
- [ ] Webhook alerts
- [ ] Production proxy (optional)
- [ ] Rolling baseline comparison

### Timeline
| Week | Deliverable |
|------|-------------|
| 61-64 | Baseline engine |
| 65-68 | Drift detection |
| 69-72 | Webhook integration |
| 73-76 | Production proxy |
| 77-80 | v0.5.0 release |

### Exit Criteria
- Baseline calibration completes
- Drift detection fires on behavioral change
- Webhook sends alerts
- Threshold tunable per deployment

---

## Phase 5: Enterprise (Months 19-24)
### Goal: Production-ready features

| Component | Current | Target | Status |
|-----------|---------|--------|--------|
| Probe Registry | Empty | Full | Build |
| SIEM Export | Stub | Working | Build |
| Enterprise Auth | Stub | Full | Build |
| Marketplace | Stub | Full | Build |

### Probe Registry

```yaml
# Probe format (tessera.probes)
id: "compound_injection_rag_tool"
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
```

### Taxonomy Mapping

```python
TAXONOMY = {
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
    }
}
```

### SIEM Export

| Provider | Format | Status |
|----------|--------|--------|
| Splunk | HEC | Build |
| Datadog | API | Build |
| Elasticsearch | Ingest | Build |
| Generic | CEF | Build |

### Deliverables (Phase 5)
- [ ] 50+ built-in probes
- [ ] garak import compatibility
- [ ] OWASP/NIST/EU AI Act mapping
- [ ] SIEM connectors (3)
- [ ] Enterprise auth (API keys, RBAC)
- [ ] Marketplace for community probes

### Timeline
| Week | Deliverable |
|------|-------------|
| 81-84 | Probe registry |
| 85-88 | SIEM exports |
| 89-92 | Enterprise auth |
| 93-96 | Marketplace |
| 97-100 | v1.0 release |

---

## Release Timeline Summary

| Version | Month | Milestone |
|---------|-------|----------|
| v0.1.0 | Now | Prototype (topology + basic scan) |
| v0.2.0 | 4 | MVP (Tier 1-2, findings API) |
| v0.3.0 | 8 | GNN trained classifier |
| v0.4.0 | 14 | Swarm execution |
| v0.5.0 | 18 | Drift detection |
| **v1.0** | **24** | Full spec implementation |

---

## Key Milestones

```
Month 4:  tessera gate --tier 1/2 works, findings API
Month 8:  GNN classifier trained, >80% accuracy  
Month 14: Swarm generates compound attack traces
Month 18: Drift detection fires on behavioral change
Month 24: Full spec (v1.0) shipped

Key Dependencies:
├── Phase 2 needs training data (critical path)
├── Phase 3 needs Phase 2 GNN (classifier feedback)
├── Phase 4 needs Phase 1 baseline
└── Phase 5 needs all prior phases
```

---

## Risks + Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| GNN cold-start | Training data scarce | Synthetic + AgentHarm |
| Swarm cost | API bills explode | Local Ollama default |
| False positives | Alert fatigue | Confidence scoring |
| Topology drift | Wrong attack surface | Auto-discovery tools |
| Timeline slip | 24 → 36 months | Scope reductions as needed |

---

## Success Metrics

| Phase | Metric | Target |
|-------|--------|-------|
| 1 | Tier 2 scan time | <5 min |
| 2 | GNN accuracy | >80% |
| 3 | Unique attack traces | 5+ |
| 4 | Drift detection | Fires on change |
| 5 | Probe count | 50+ |
| ALL | Test coverage | >80% |