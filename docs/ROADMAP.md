# TESSERA Product Roadmap

**Version:** 1.0  
**Date:** April 14, 2026  
**Current Status:** MVP Complete (Phase 1-2)  

---

## 1. Current Product State

### What's Built (MVP)

| Component | Files | Status |
|------------|-------|--------|
| Topology Modeler | 2 | ✅ Working |
| CI/CD Gate (Tier 1-3) | 1 | ✅ Working |
| Findings API | 3 | ✅ Working |
| Probe Registry | 2 | ✅ Working |
| Swarm Engine (prototype) | 2 | ⚠️ Mock-only |
| Classifier (rule-based) | 1 | ✅ Working |
| Fingerprint Engine | 1 | ⚠️ Mock-only |
| CLI + Tests | 1 + 2 | ✅ Working |

**Test Coverage:** 9 tests, all passing  
**CLI Commands:** `tessera scan`, `tessera topology`, `tessera findings`

### Technical Gaps to Address

| Gap | Severity | Impact |
|-----|----------|--------|
| No real LLM backbone integration | High | Can't run actual swarm attacks |
| Fingerprint needs sentence-transformers | Medium | Drift detection needs ML deps |
| No GNN training data | High | Can't validate compound classifier |
| No persistence layer | Medium | Scan results aren't saved |
| No webhook/alerting | Low | Findings only via API |

---

## 2. User Personas

### Persona A: Security Engineer (Primary)

**Name:** Alex  
**Role:** Enterprise security team, builds AI products  
**Goals:** Find vulnerabilities before production deployment  
**Pain Points:**

- "Current tools don't catch multi-hop attacks"
- "Scans take hours, can't fit in CI/CD"
- "No way to track drift over time"

**Value from TESSERA:**

- Compound failure detection
- Tiered CI/CD (<30s, <5m, <60m)
- Baseline fingerprinting

**Acceptance Criteria:**

- [ ] Tier 1 scan completes in <30 seconds
- [ ] Attack surface visualized from topology YAML
- [ ] Findings export to SARIF for GitHub

### Persona B: ML Engineer (Secondary)

**Name:** Jordan  
**Role:** Builds RAG/agentic systems for product  
**Goals:** Verify safety of AI pipeline before release  
**Pain Points:**

- "garak only tests endpoints, not my full system"
- "No way to test RAG → tool call chains"

**Value from TESSERA:**

- Topology graph models their full pipeline
- Multi-hop attack detection

**Acceptance Criteria:**

- [ ] Define system topology as YAML
- [ ] Run compound attacks against paths
- [ ] See which nodes fail

### Persona C: Researcher (Tertiary)

**Name:** Sam  
**Role:** AI safety research, publishes papers  
**Goals:** Discover new attack patterns, build benchmarks  
**Pain Points:**

- "Need better benchmarks for compound attacks"
- "No standardized taxonomy"

**Value from TESSERA:**

- Probe registry with taxonomy
- Extensible framework

**Acceptance Criteria:**

- [ ] Add custom probes
- [ ] Export findings in standard formats

---

## 3. Feature Prioritization (RICE)

### Candidate Features for Next Quarter

| Feature | Reach | Impact | Confidence | Effort | RICE Score | Priority |
|---------|-------|--------|-------------|--------|-------------|----------|
| Tier 1 CI/CD gate integration | 8 | 3 | 95% | 1 | 228 | 🥇 P0 |
| LLM backbone (OpenAI/Ollama) | 10 | 3 | 90% | 2 | 540 | 🥈 P0 |
| Persistence (SQLite) | 8 | 2 | 90% | 2 | 288 | 🥉 P1 |
| GARAK probe import | 6 | 2 | 80% | 2 | 192 | P1 |
| Drift monitoring | 5 | 3 | 60% | 3 | 270 | P1 |
| Webhook alerting | 4 | 2 | 80% | 1 | 128 | P2 |
| SIEM export (Splunk) | 3 | 2 | 70% | 2 | 84 | P2 |
| GNN classifier training | 3 | 3 | 40% | 5 | 180 | P3 |

**Recommendation:** Focus on P0+P1 for next quarter

---

## 4. User Stories & Acceptance Criteria

### Sprint 1: CI/CD Integration

**Epic:** "As a Security Engineer, I want TESSERA in my CI/CD pipeline"

**Story 1.1:** "As Alex, I want TESSERA fail on critical findings"
- AC: `tessera gate --tier 1` exits 1 when severity >= high
- AC: Exit 0 when scan passes

**Story 1.2:** "As Alex, I want GitHub Actions template"
- AC: YAML template in `scripts/github-actions.yml`
- AC: Runs on PR to prompt files

**Story 1.3:** "As Alex, I want SARIF output"
- AC: `tessera findings --format sarif` works
- AC: Importable to GitHub Security tab

### Sprint 2: LLM Integration

**Epic:** "As Jordan, I want real swarm attacks, not mocks"

**Story 2.1:** "As Jordan, I want Ollama backbone"
- AC: `--backbone ollama` uses local Llama3
- AC: Falls back gracefully if unavailable

**Story 2.2:** "As Jordan, I want OpenAI backbone"
- AC: `--backbone openai --model gpt-4o-mini`
- AC: Cost estimate shown before run

**Story 2.3:** "As Jordan, I want to configure swarm agents"
- AC: `--agent-count 5` configures N agents
- AC: `--max-iterations 50` limits runs

### Sprint 3: Persistence

**Epic:** "As Alex, I want scan history"

**Story 3.1:** "As Alex, I want SQLite storage"
- AC: Scans saved to `~/.tessera/scans.db`
- AC: `tessera scans list` shows history

**Story 3.2:** "As Alex, I want baseline fingerprints"
- AC: Calibration creates fingerprint
- AC: Saved and loadable

### Sprint 4: Probe Ecosystem

**Epic:** "As Sam, I want extensible probes"

**Story 4.1:** "As Sam, I want GARAK import"
- AC: `tessera probes import-garak /path/to/garak`
- AC: Probes converted to TESSERA format

---

## 5. Roadmap Timeline

### Q2 2026 (Months 1-3) - ✅ COMPLETE

| Sprint | Focus | Deliverables | Status |
|--------|-------|--------------|--------|
| 1 | CI/CD Integration | GitHub Actions, SARIF, exit codes | ✅ |
| 2 | LLM Backbone | Ollama + OpenAI adapters | ✅ |
| 3 | Persistence | SQLite, scan history | ✅ |
| 4 | Probe Ecosystem | GARAK import, custom probes | ✅ |

### Q3 2026 (Months 4-6) - IN PROGRESS

| Sprint | Focus | Deliverables |
|--------|-------|--------------|
| 5 | Drift Monitoring | Fingerprint calibration, MMD detection |
| 6 | Swarm Evolution | Adaptive attack generation |
| 7 | Enterprise | Multi-tenant, RBAC |
| 8 | SIEM Integration | Splunk, Datadog connectors |

**Success Metrics Q3:**

- [ ] Drift detection fires on behavioral shift
- [ ] 100+ unique attack traces generated
- [ ] Production customer pilots

### Q4 2026 (Months 7-12)

| Sprint | Focus | Deliverables |
|--------|-------|--------------|
| 9 | GNN Training | Real compound classifier |
| 10 | Cloud | SaaS deployment |
| 11 | Marketplace | Probe community |
| 12 | v1.0 Release | Production-ready |

**Success Metrics Q4:**

- [ ] GNN classifier trained on real data
- [ ] 10+ production deployments
- [ ] v1.0 with enterprise SLA

---

## 6. Build vs Buy Decision

| Component | Build/Buy | Rationale |
|-----------|-----------|-----------|
| LLM API (OpenAI) | Buy | Their infrastructure, we integrate |
| Embedding model | Buy | sentence-transformers open source |
| Vector DB | Buy | Pinecone/Weaviate existing |
| SIEM | Buy | Splunk/Datadog APIs |
| Probe content | Build | Our IP, extensible |
| GNN classifier | Build | Novel, our innovation |
| Platform | Build | Our core product |

---

## 7. Success Metrics Framework

### Primary Metrics (North Star)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Active users | 100+ | Weekly unique CLI invocations |
| Scans run | 10K/month | API + CLI |
| Vulnerabilities found | 1000+ | Per quarter |

### Secondary Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| CI/CD adoption | 50+ teams | GitHub Actions template usage |
| Probe extensions | 20+ | Community contributions |
| Drift alerts | 500+/month | Production monitoring |

### Target Customer Profile

**Company Type:** Mid-market SaaS, 50-500 employees  
**Use Case:** AI product security testing  
**Budget:** $5K-50K/year  
**Decision Maker:** Security Engineering Manager  

---

## 8. Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| LLM costs spiral | High | Medium | Tiered backbone, local default |
| False positive fatigue | High | High | Confidence scoring, sliding window |
| No community adoption | Medium | High | Developer relations, free tier |
| Cloud provider feature absorption | Medium | Low | Focus on compound failures |
| GNN training data unavailable | High | High | Rule-based fallback |

---

## 9. Next Steps (Immediate)

**Week 1:**

- [ ] Create GitHub Actions template
- [ ] Add exit code handling to gate
- [ ] Implement SARIF export

**Week 2:**

- [ ] Integrate OpenAI adapter
- [ ] Add cost estimation
- [ ] Create getting started guide

**Week 3:**

- [ ] SQLite persistence
- [ ] Scan history CLI
- [ ] Documentation website

---

## Appendix A: Competitive Position

| Competitor | Their Focus | Our Differentiation |
|-----------|-------------|----------------------|
| garak | Static probes | Compound detection, topology |
| PyRIT | Multi-turn attacks | Swarm, drift monitoring |
| DeepTeam | Vulnerability categories | Open-source, extensible |
| AWS Bedrock Guardrails | Content filtering | Full system testing |
| Azure AI Safety | Content filtering | Full system testing |

**Strategic Position:** "The EDR for AI Systems" - behavioral security testing beyond endpoint scanning.

---

*Document Owner:* Product Team  
*Review Cycle:* Monthly  
*Next Review:* May 14, 2026