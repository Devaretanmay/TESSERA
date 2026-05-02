# TESSERA Lab - Real-World Attack Validation System

A production-style attack lab for validating TESSERA scanner against real AI agent vulnerabilities.

## Quick Start

```bash
cd /Users/tanmaydevare/Tanmay/TESSERA

# Run all attack scenarios
./tessera-lab/scripts/run_scans.sh

# View comparison report
cat tessera-lab/reports/COMPARISON.md
```

## Project Structure

```
tessera-lab/
├── topology-maps/        # YAML definitions of AI agent topologies
│   ├── base.yaml        # Base AI agent (11 findings)
│   ├── safe_baseline.yaml  # Safe config (1 finding)
│   ├── attack_rag_tool.yaml    # CFPE-0001 test
│   ├── attack_memory_poison.yaml  # CFPE-0002 test
│   └── attack_multihop.yaml    # CFPE-0005 test
├── attack-scenarios/     # Detailed attack documentation
│   ├── scenario_01_rag_tool.md
│   ├── scenario_02_memory_poison.md
│   └── scenario_03_multihop.md
├── scanner-runs/        # TESSERA scan outputs
│   ├── json/           # JSON format results
│   ├── sarif/          # SARIF v2.1.0 results
│   └── html/            # HTML reports
├── scripts/
│   └── run_scans.sh    # Automated scan runner
└── reports/
    └── COMPARISON.md   # Side-by-side comparison
```

## Attack Scenarios

| ID | Name | CFPE Pattern | Findings |
|----|------|-------------|----------|
| 1 | RAG to Tool Exploitation | CFPE-0001 | 3 |
| 2 | Memory Poisoning | CFPE-0002 | 3 |
| 3 | Multi-hop Attack Chain | CFPE-0005 | 9 |
| 4 | Data Exfiltration | CFPE-0007 | - |
| 5 | Trust Boundary Bypass | CFPE-0004 | - |

## Results

### Multi-hop Detection (CFPE-0005)
```
Multi-hop attack chain (4 hops): user_input -> web_api -> chat_llm -> conversation_history
Multi-hop attack chain (4 hops): user_input -> web_api -> chat_llm -> payment_api
Multi-hop attack chain (4 hops): user_input -> web_api -> chat_llm -> database
Multi-hop attack chain (4 hops): web_api -> chat_llm -> rag_corpus -> search_tool
```

### Detection Coverage

| CFPE Rule | Attack Type | Detection |
|----------|------------|-----------|
| CFPE-0001 | RAG → Tool | ✅ |
| CFPE-0002 | Memory Poisoning | ✅ |
| CFPE-0004 | Trust Boundary | ✅ |
| CFPE-0005 | Multi-hop Chain | ✅ |
| CFPE-0007 | Data Exfiltration | ✅ |

## Using TESSERA

```bash
# Scan a topology
tessera scan --config tessera-lab/topology-maps/attack_multihop.yaml --format json

# Scan with SARIF output (for GitHub Security)
tessera scan --config tessera-lab/topology-maps/attack_multihop.yaml --format sarif --output results.sarif

# Explain a rule
tessera explain CFPE-0005

# List all rules
tessera list-rules
```

## Integration with CI/CD

### GitHub Actions
```yaml
- name: Run TESSERA scan
  run: |
    tessera scan --config topology.yaml --format sarif --output results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook
```yaml
repos:
  - repo: local
    hooks:
      - id: tessera-scan
        name: TESSERA Security Scan
        entry: tessera scan --format sarif
        types: [yaml]
        files: ^topology-maps/
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  AI Agent System                       │
│  user_input → web_api → chat_llm → [tools,memory,RAG] │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│            TESSERA Scanner                          │
│  Topology YAML → Detection Engine → Findings          │
│  CFPE-0001 to CFPE-0010 patterns               │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│              Output Formats                       │
│  JSON | SARIF v2.1.0 | HTML | Text            │
└─────────────────────────────────────────────────────────────┘
```

## Success Criteria

- [x] TESSERA detects at least 3 compound chains
- [x] Each detection maps to real app behavior
- [x] Outputs render in JSON + SARIF
- [x] Attacks are reproducible
- [x] Demo can be run by others

## Next Steps

1. Integrate with real AI app (Flowise, LangFlow, etc.)
2. Add more attack scenarios
3. Build automated regression testing
4. Create visual dashboard

## License

MIT - Same as TESSERA