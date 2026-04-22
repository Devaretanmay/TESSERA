# Research-Driven Engineering Changes (April 22, 2026)

This note records the human-factors and software-comprehension research used to guide the latest TESSERA code-quality refactor.

## Papers and Sources

1. NIST, *Security Fatigue* (IEEE Software, 2016)  
   https://csrc.nist.gov/pubs/journal/2016/09/security-fatigue/final
2. Vance et al., *Repetition of Computer Security Warnings Results in Differential Repetition Suppression Effects as Revealed With Functional MRI* (Frontiers in Psychology, 2020)  
   https://pmc.ncbi.nlm.nih.gov/articles/PMC7751389/
3. Ferreira et al., *Can EEG Be Adopted as a Neuroscience Reference for Assessing Software Programmers' Cognitive Load?* (Sensors, 2021)  
   https://www.mdpi.com/1424-8220/21/7/2338
4. Baron et al., *An Empirical Validation of Cognitive Complexity as a Measure of Source Code Understandability* (arXiv:2007.12520, 2020)  
   https://arxiv.org/abs/2007.12520
5. Graziotin et al., *Correlates of Programmer Efficacy and Their Link to Experience: A Combined EEG and Eye-Tracking Study* (arXiv:2303.07071, 2023)  
   https://arxiv.org/abs/2303.07071

## Design Implications Applied

| Research signal | Engineering implication | Implemented change |
|---|---|---|
| Users experience security fatigue under repeated/noisy warnings. | Reduce repeated findings and make outputs more focused. | Added finding deduplication in scanner flow before formatting. |
| Habituation reduces warning salience over repeated exposure. | Avoid unnecessary duplicate alerts in repeated path patterns. | Dedup key now includes rule id + severity + description + normalized edges. |
| Developer cognitive load increases with ambiguous and duplicated code paths. | Remove duplicated parser logic and keep one conversion path. | Refactored topology loader to centralize YAML parsing + graph build logic. |
| Understandability improves with clearer structure and lower incidental complexity. | Fix confusing behavior and strict contracts in API/CLI paths. | Fixed CLI success path (`Error: 0` bug), improved scan-to-dict contract and API validation behavior. |
| Tooling should be resilient against untrusted content rendered in UX channels. | Treat rendered reports as hostile output sinks. | Added HTML escaping in report formatter for finding text, edge labels, and remediation content. |

## Validation

- `ruff check src tests` passes.
- `pytest -q` passes (7 tests).
- Added targeted regression tests for loader consistency, CLI exit behavior, HTML escaping, and scanner remediation/dict contract.
