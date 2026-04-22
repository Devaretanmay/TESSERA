# TESSERA v2.0 Product Requirements Document

## Version: 1.0
## Date: April 2026
## Status: Draft

---

# 1. Executive Summary

TESSERA is an AI agent security scanner designed to detect compound attack chains in AI/Agent system topologies. This PRD defines the roadmap for TESSERA v2.0, which expands from a simple rule-based CFPE scanner to a comprehensive multi-layer security platform.

**Current State (v1.x):**
- 3 CFPE detection patterns
- Python library + CLI
- YAML topology input

**Target State (v2.0):**
- Multi-layer detection (CFPE + Behavioral + LLM)
- SARIF output for CI/CD
- GitHub Actions integration
- Optional LLM-powered analysis
- Comprehensive attack chain detection

---

# 2. Problem Statement

## 2.1 Market Problem

AI agents and LLM-integrated applications are rapidly adopting, but security tools have not kept pace:

| Problem | Impact | Evidence |
|---------|--------|----------|
| No specialized AI agent scanners | Vulnerabilities undetected | 540% surge in prompt injection attacks (2025) |
| Existing tools miss compound attacks | Multi-hop attacks evade detection | Single-hop scanners only |
| No CI/CD integration | Security not automated | Manual review only |
| False positives overwhelming | Alert fatigue | Generic scanners |

## 2.2 User Problems

1. **Security Teams**: Cannot detect AI agent vulnerabilities in their deployments
2. **DevSecOps**: Need automated scanning in CI/CD pipelines
3. **AI Engineers**: Need guidance on securing agent architectures
4. **Auditors**: Need comprehensive reports for compliance

---

# 3. Target Users & Personas

## 3.1 Primary Personas

### Persona 1: Security Engineer (Alex)

**Role:** Enterprise Security Team
**Goals:**
- Detect vulnerabilities in AI agent deployments
- Integrate security into CI/CD
- Generate compliance reports
- Stay ahead of emerging threats

**Pain Points:**
- Generic security tools miss AI-specific vulnerabilities
- Manual code review is time-consuming
- False positives from rule-based scanners

**Success Criteria:**
- Automated vulnerability detection
- Integration with existing security tools
- Accurate findings with low false positive rate

---

### Persona 2: DevSecOps Engineer (Jordan)

**Role:** Platform/DevOps Team
**Goals:**
- Embed security into CI/CD pipelines
- Fail builds on critical findings
- Generate SARIF reports for GitHub
- Scan on every PR/commit

**Pain Points:**
- No SARIF output support
- Manual security gates
- Poor integration with GitHub

**Success Criteria:**
- GitHub Actions workflow
- SARIF format support
- Exit codes for build failure

---

### Persona 3: AI/ML Engineer (Sam)

**Role:** AI Application Developer
**Goals:**
- Build secure AI agents
- Understand security implications
- Follow best practices
- Secure their RAG pipelines

**Pain Points:**
- Unaware of AI-specific attack vectors
- No guidance on secure architecture
- CFPE patterns too basic

**Success Criteria:**
- Educational security output
- Remediation guidance
- Trust architecture recommendations

---

# 4. Competitive Landscape

## 4.1 Alternative Solutions

| Tool | Strengths | Weaknesses | TESSERA Differentiation |
|------|-----------|------------|------------------------|
| **Cisco skill-scanner** | Multi-engine, LLM analysis | Agent skills only | Graph-based topology analysis |
| **Medusa** | 9,600+ rules | Generic AI security | Compound attack chains |
| **Runner-Guard** | CI/CD focus | GitHub Actions only | Broader agent support |
| **Pysa** | Taint tracking | Python-only | AI agent patterns |
| **CodeQL** | Comprehensive | Not AI-specific | AI-specific focus |

## 4.2 TESSERA Differentiation

1. **Compound Attack Chain Detection**: Focus on multi-hop attacks across agent components
2. **Topology-Based Analysis**: Visualize and analyze agent architecture graphs
3. **CFPE + Behavioral + LLM**: Layered detection approach
4. **Developer Experience**: CLI-first, Python library, GitHub-native

---

# 5. Product Vision & Strategy

## 5.1 Vision Statement

> TESSERA becomes the leading open-source security scanner for AI agents, enabling teams to detect and prevent compound attack chains in production AI deployments through automated, comprehensive, and actionable security analysis.

## 5.2 Strategic Pillars

| Pillar | Description | Priority |
|--------|-------------|----------|
| **Detection Excellence** | Multi-layer security detection | P0 |
| **Developer Experience** | CLI-first, Python-native | P0 |
| **CI/CD Native** | GitHub Actions, SARIF, pre-commit | P1 |
| **Extensibility** | Plugin architecture | P2 |

## 5.3 Success Definition

| Metric | Target | Timeline |
|--------|--------|----------|
| GitHub Stars | 1,000+ | 12 months |
| Active Users | 100+ orgs | 12 months |
| Detection Coverage | 10+ CFPE patterns | 6 months |
| False Positive Rate | <15% | 6 months |
| CI/CD Adoption | 50+ GitHub Actions | 9 months |

---

# 6. Requirements

## 6.1 Core Detection Capabilities

### Requirement 1: CFPE Rule Engine

**Description:** Expand and maintain the CFPE detection rules

**Current Patterns:**
- CFPE-0001: RAG to Tool (HIGH)
- CFPE-0002: Memory Poisoning (CRITICAL)
- CFPE-0004: Trust Boundary Bypass (HIGH)

**Required Patterns (v2.0):**

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| CFPE-0001 | RAG to Tool | HIGH | LLM → RAG → Tool chain |
| CFPE-0002 | Memory Poisoning | CRITICAL | LLM → memory_store (write) |
| CFPE-0003 | External → Database | HIGH | Untrusted → database direct |
| CFPE-0004 | Trust Boundary Bypass | HIGH | Cross-boundary untrusted flow |
| CFPE-0005 | Multi-hop Chain (3+) | HIGH | 3+ edge attack path |
| CFPE-0006 | Tool → Tool Chaining | MEDIUM | Tool calls tool |
| CFPE-0007 | Sensitive Data Exfiltration | CRITICAL | LLM → external_service |
| CFPE-0008 | RAG Context Injection | HIGH | User → RAG injection |
| CFPE-0009 | MCP Config Attack | HIGH | Malicious MCP server |
| CFPE-0010 | Agent Skill Injection | HIGH | SKILL.md compromise |

**Acceptance Criteria:**
- [ ] All 10 patterns implemented
- [ ] Each pattern has remediation guidance
- [ ] Severity mapping aligns with CVSS

---

### Requirement 2: Behavioral Analysis Engine

**Description:** Track data flow through the agent topology graph

**Features:**

| Feature | Description | Priority |
|---------|-------------|----------|
| Path Discovery | Find all paths source → sink | P0 |
| Trust Boundary Tracking | Monitor crossing events | P0 |
| Multi-hop Analysis | 3+ edge path detection | P1 |
| Taint Propagation | User input → dangerous sink | P2 |

**Technical Implementation:**

```
Data Flow Analysis Module
├── Source Detection
│   ├── user_input (untrusted)
│   ├── external (untrusted)
│   └── user_controlled
│
├── Sink Classification
│   ├── CRITICAL: database (write), shell_exec
│   ├── HIGH: tool, external_service, memory_store
│   └── MEDIUM: rag_corpus, api
│
├── Path Finding
│   ├── BFS from sources
│   ├── Track trust boundaries
│   └── Report dangerous paths
│
└── Risk Scoring
    ├── Path length weight
    ├── Trust crossing penalty
    └── Sink severity sum
```

**Acceptance Criteria:**
- [ ] Identify all paths from user input to sensitive sinks
- [ ] Detect trust boundary crossings
- [ ] Report path with highest risk score
- [ ] Performance: <2s for 100-node graphs

---

### Requirement 3: LLM-Powered Analysis (Optional)

**Description:** AI-powered semantic analysis for advanced detection

**Features:**

| Feature | Description | Mode |
|---------|-------------|------|
| Semantic Risk Assessment | Analyze topology semantically | Optional |
| Prompt Injection Detection | Check for injection patterns | Optional |
| Anomaly Detection | Behavioral baseline + deviation | Optional |
| False Positive Filtering | LLM-as-judge consensus | Optional |

**Architecture:**

```
LLM Analysis Module
├── Input: Topology JSON + Context
├── Processing:
│   ├── Intent Classification (system vs user)
│   ├── Risk Scoring (semantic)
│   └── Consensus (multiple runs)
├── Output:
│   ├── Risk Level (safe/low/medium/high/critical)
│   ├── Findings with explanations
│   └── Confidence score
└── Configuration:
    ├── Provider: OpenAI, Anthropic, Ollama
    ├── Model selection
    └── Temperature, tokens
```

**Acceptance Criteria:**
- [ ] Optional enable/disable
- [ ] Clear API for LLM configuration
- [ ] Fallback when LLM unavailable
- [ ] Cost tracking and limits

---

### Requirement 4: Output & Reporting

**Description:** Multiple output formats for different audiences

**Required Formats:**

| Format | Use Case | Priority |
|--------|----------|----------|
| JSON | Machine parsing | P0 |
| SARIF | GitHub Code Scanning | P0 |
| Text | CLI output | P0 |
| HTML | Report generation | P1 |
| Markdown | Documentation | P2 |

**SARIF Schema:**

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "TESSERA",
        "version": "2.0.0",
        "rules": [{
          "id": "CFPE-0001",
          "name": "RAG to Tool",
          "shortDescription": { "text": "RAG to Tool execution chain" }
        }]
      }
    },
    "results": [{
      "ruleId": "CFPE-0001",
      "level": "warning",
      "message": { "text": "RAG to Tool chain detected" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "topology.yaml" }
        }
      }]
    }]
  }]
}
```

**Acceptance Criteria:**
- [ ] SARIF v2.1.0 compliant
- [ ] GitHub Code Scanning integration verified
- [ ] JSON output with all findings
- [ ] Human-readable text format

---

### Requirement 5: CI/CD Integration

**Description:** Seamless integration with development workflows

**Features:**

| Integration | Description | Priority |
|------------|-------------|----------|
| GitHub Actions | Workflow template | P0 |
| Pre-commit Hook | Local scanning | P1 |
| GitLab CI | Alternative CI | P2 |
| GitHub MCP Server | AI assistant integration | P2 |

**GitHub Actions Template:**

```yaml
name: TESSERA Security Scan

on:
  push:
    paths:
      - '**/*.yaml'
      - '**/*.yml'
  pull_request:
    paths:
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  tessera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      
      - name: Run TESSERA Scan
        uses: tessera-security/tessera-action@v1
        with:
          config: ${{ matrix.config }}
          format: sarif
          output: results.sarif
          fail-on-severity: high
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
          category: tessera
```

**Acceptance Criteria:**
- [ ] GitHub Actions verified working
- [ ] Pre-commit hook functional
- [ ] Exit codes correctly signal build failure
- [ ] SARIF appears in GitHub Security tab

---

### Requirement 6: User Experience

**Description:** Intuitive CLI and library experience

**CLI Features:**

| Command | Description |
|---------|-------------|
| `tessera scan <file>` | Scan topology file |
| `tessera scan-dir <dir>` | Scan directory |
| `tessera init` | Create config |
| `tessera list-rules` | List detection rules |
| `tessera explain <rule>` | Explain a rule |

**Python API:**

```python
from tessera import Tesseract

# Simple usage
scanner = Tesseract()
findings = scanner.scan("topology.yaml")

# With options
scanner = Tesseract(
    enabled_rules=["CFPE-0001", "CFPE-0002"],
    behavioral=True,
    llm_enabled=True,
    llm_provider="openai",
    output_format="sarif"
)

# Full control
scanner = Tesseract(config="tessera.yaml")
report = scanner.scan_with_options(
    topology=topology,
    include_remediation=True,
    include_explanations=True,
    min_severity="medium"
)
```

**Acceptance Criteria:**
- [ ] CLI with scan, init, list, explain
- [ ] Python library with all options
- [ ] Configuration file support
- [ ] Colored CLI output

---

# 7. Technical Architecture

## 7.1 System Design

```
┌─────────────────────────────────────────────────────────────┐
│                        TESSERA v2.0                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Input    │    │   Input    │    │   Input    │     │
│  │  (CLI)     │    │ (Python)   │    │  (GitHub   │     │
│  │            │    │            │    │   Actions) │     │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘     │
│         │                   │                   │            │
│         └───────────────────┼───────────────────┘            │
│                             ▼                                │
│                  ┌────────────────┐                         │
│                  │   Scanner     │                         │
│                  │   Engine      │                         │
│                  └───────┬────────┘                         │
│                          │                                   │
│    ┌─────────────────────┼─────────────────────┐            │
│    ▼                     ▼                     ▼            │
│ ┌──────────┐      ┌──────────────┐      ┌──────────┐      │
│ │   CFPE   │      │  Behavioral  │      │   LLM    │      │
│ │  Rules   │      │  Analysis    │      │  Detect  │      │
│ │          │      │              │      │          │      │
│ │ -0001    │      │ - Path find  │      │ - Semantic│      │
│ │ -0002    │      │ - Taint      │      │ - Anomaly│      │
│ │ -...     │      │ - Trust     │      │ - Judge  │      │
│ └────┬─────┘      └──────┬───────┘      └─────┬────┘      │
│      │                   │                     │            │
│      └───────────────────┼─────────────────────┘            │
│                          ▼                                   │
│                  ┌────────────────┐                         │
│                  │ Meta-Analyzer │ ← Filter & Prioritize    │
│                  └───────┬────────┘                         │
│                          │                                   │
│    ┌─────────────────────┼─────────────────────┐            │
│    ▼                     ▼                     ▼            │
│ ┌──────────┐      ┌──────────────┐      ┌──────────┐      │
│ │   JSON   │      │    SARIF     │      │   Text   │      │
│ │  Output  │      │   Output     │      │  Output  │      │
│ └──────────┘      └──────────────┘      └──────────┘      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## 7.2 Component Design

| Component | Responsibility | Public API |
|-----------|----------------|------------|
| `scanner` | Orchestration | `scan()`, `scan_file()`, `scan_dir()` |
| `cfpe` | Rule engine | `detect()`, `list_rules()` |
| `behavioral` | Dataflow analysis | `analyze_paths()`, `taint_track()` |
| `llm` | AI analysis | `assess()`, `filter_fp()` |
| `output` | Formatters | `to_json()`, `to_sarif()`, `to_text()` |
| `cli` | User interface | CLI commands |

---

# 8. Roadmap

## 8.1 Phase Breakdown

### Phase 1: Foundation (Months 1-2)

**Goal:** Establish core infrastructure

| Week | Deliverable | Owner |
|------|-------------|-------|
| 1-2 | SARIF output implementation | |
| 3-4 | GitHub Actions workflow | |
| 5-6 | CFPE-0003 to CFPE-0006 | |
| 7-8 | Behavioral analysis core | |

**Success Metrics:**
- SARIF validated with GitHub
- GitHub Actions verified
- 6 CFPE patterns working
- Path analysis functional

---

### Phase 2: Intelligence (Months 3-4)

**Goal:** Add AI-powered capabilities

| Week | Deliverable | Owner |
|------|-------------|-------|
| 9-10 | LLM integration core | |
| 11-12 | Semantic analysis | |
| 13-14 | False positive filtering | |
| 15-16 | Prompt injection detection | |

**Success Metrics:**
- Optional LLM mode working
- Semantic risk scoring
- 30% FP reduction with meta-analyzer
- Injection patterns detected

---

### Phase 3: Ecosystem (Months 5-6)

**Goal:** Expand integrations and coverage

| Week | Deliverable | Owner |
|------|-------------|-------|
| 17-18 | CFPE-0007 to CFPE-0010 | |
| 19-20 | Pre-commit hook | |
| 21-22 | HTML report generation | |
| 23-24 | MCP server support | |

**Success Metrics:**
- 10 CFPE patterns
- Pre-commit functional
- Reports generation
- MCP integration

---

### Phase 4: Scale (Months 7-12)

**Goal:** Grow adoption and features

| Quarter | Focus |
|---------|-------|
| Q3 | Performance, plugins, extensibility |
| Q4 | Enterprise features, team management |

**Future Features:**
- Plugin architecture
- Team/organization management
- Dashboard
- API server
- Slack/Teams notifications

---

## 8.2 Milestone Timeline

```
Month:  1    2    3    4    5    6    7-12
        │    │    │    │    │    │    │
        ▼    ▼    ▼    ▼    ▼    ▼    ▼
Phase 1 ├────┴────┤
        │  Foundation │
        │  - SARIF   │
        │  - Actions  │
        │  - CFPE 6   │
        │  - Behavioral│
        │
Phase 2 ├───────────┴───────┤
        │   Intelligence    │
        │   - LLM core     │
        │   - Semantic     │
        │   - FP filter    │
        │
Phase 3 ├─────────────────┴───────┤
        │     Ecosystem             │
        │  - CFPE 10               │
        │  - Pre-commit            │
        │  - Reports               │
        │  - MCP                   │
        │
Phase 4 ├─────────────────────────┴─────►
        │         Scale                  │
        │  - Plugins                    │
        │  - Enterprise                 │
        │  - Dashboard                  │
```

---

# 9. Success Metrics

## 9.1 Product Metrics

| Metric | Target v1.x | Target v2.0 | Measurement |
|--------|-------------|-------------|-------------|
| CFPE Patterns | 3 | 10 | Count |
| Detection Rate | 60% | 85% | Benchmark |
| False Positive | 30% | <15% | User feedback |
| Scan Time (100 nodes) | 1s | <2s | Benchmark |
| SARIF Support | No | Yes | GitHub verification |

## 9.2 Adoption Metrics

| Metric | 3 Months | 6 Months | 12 Months |
|--------|----------|----------|-----------|
| GitHub Stars | 200 | 500 | 1,000 |
| Active Users | 20 | 50 | 100 |
| GitHub Actions | 10 | 30 | 50 |
| PRs/Issues | 5 | 15 | 30 |

## 9.3 Quality Metrics

| Metric | Target |
|--------|--------|
| Test Coverage | >80% |
| Documentation | Complete API + CLI |
| Release Frequency | Monthly |
| Issue Response | <48 hours |

---

# 10. Risks & Mitigation

## 10.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| LLM integration complexity | High | Medium | Start with simple use cases |
| Performance degradation | Medium | High | Benchmark every release |
| False positives | High | High | Meta-analyzer, user feedback |

## 10.2 Market Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Competition | Medium | High | Focus on differentiation |
| Tooling changes | Low | Medium | Version pinning |
| AI landscape shift | Medium | Low | Extensible architecture |

---

# 11. Dependencies

## 11.1 External

| Dependency | Purpose | Alternative |
|------------|---------|-------------|
| OpenAI API | LLM analysis | Anthropic, Ollama |
| GitHub API | Actions, SARIF | Standalone only |
| PyYAML | YAML parsing | ruamel.yaml |
| NetworkX | Graph analysis | Custom implementation |

## 11.2 Internal

- Core topology models
- Detection patterns
- Output formatters

---

# 12. Appendix

## 12.1 Glossary

| Term | Definition |
|------|------------|
| CFPE | Compound Failure Pattern Engine |
| SARIF | Static Analysis Results Interchange Format |
| Taint | Untrusted user-controlled data |
| Trust Boundary | Boundary between trusted/untrusted zones |
| Compound Attack | Multi-step attack chain |

## 12.2 References

- OWASP Top 10 for LLM Applications 2025
- Cisco skill-scanner architecture
- GitHub SARIF specification
- Tainter/Pysa taint analysis

---

# Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | April 2026 | TESSERA Team | Initial PRD |

---

*This PRD defines the complete roadmap for TESSERA v2.0. All features are subject to prioritization based on user feedback and resource availability.*
