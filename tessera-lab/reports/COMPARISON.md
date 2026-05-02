# TESSERA Lab - Attack Comparison Report

## CFPE Detection Summary

| Topology | CFPE-0001 | CFPE-0002 | CFPE-0004 | CFPE-0005 | CFPE-0007 | Total |
|----------|-----------|-----------|-----------|-----------|-----------|-------|
| attack_memory_poison | 0 | 2 | 1 | 0 | 0 | 3 |
| attack_multihop | 1 | 1 | 2 | 4 | 1 | 9 |
| attack_rag_tool | 1 | 0 | 1 | 1 | 0 | 3 |
| base | 1 | 2 | 2 | 5 | 1 | 11 |
| safe_baseline | 0 | 0 | 1 | 0 | 0 | 1 |

## Risk Assessment Summary

| Topology | Risk Score | Risk Level | Attack Paths | Boundary Violations |
|----------|------------|------------|--------------|---------------------|
| attack_memory_poison | 0.48/10 | info | 11 | 4 |
| attack_multihop | 6.8/10 | high | 20 | 278 |
| attack_rag_tool | 2.28/10 | low | 13 | 5 |
| base | 3.32/10 | low | 20 | 27 |
| safe_baseline | 1.47/10 | info | 6 | 2 |

---
**Generated:** 2026-04-24
