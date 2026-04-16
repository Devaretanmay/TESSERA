"""Built-in TESSERA probes for common vulnerability patterns."""

from tessera.probes.models import Probe, FailureCategory, AttackPrimitive, Severity


BUILTIN_PROBES = [
    Probe(
        id="compound_injection_rag_tool",
        name="Compound RAG→Tool Injection",
        version="1.0",
        failure_category=FailureCategory.COMPOUND_CHAIN,
        severity=Severity.CRITICAL,
        taxonomy_tags={"owasp": "LLM01,LLM06", "nist": "PR.AIP-2"},
        description="Tests for RAG injection leading to tool misuse",
        attack_primitive=AttackPrimitive.INJECTION,
    ),
    Probe(
        id="compound_memory_poisoning",
        name="Memory Poisoning → Model Behavior",
        version="1.0",
        failure_category=FailureCategory.COMPOUND_CHAIN,
        severity=Severity.CRITICAL,
        taxonomy_tags={"owasp": "LLM01", "nist": "PR.AIP-2"},
        description="Tests for memory poisoning affecting model behavior",
        attack_primitive=AttackPrimitive.ESCALATION,
    ),
    Probe(
        id="compound_tool_chain",
        name="Tool Chain Escalation",
        version="1.0",
        failure_category=FailureCategory.COMPOUND_CHAIN,
        severity=Severity.HIGH,
        taxonomy_tags={"owasp": "LLM06"},
        description="Tests for multiple tool calls in sequence",
        attack_primitive=AttackPrimitive.ESCALATION,
    ),
    Probe(
        id="atomic_instruction_override",
        name="Direct Instruction Override",
        version="1.0",
        failure_category=FailureCategory.ATOMIC_INJECTION,
        severity=Severity.HIGH,
        taxonomy_tags={"owasp": "LLM01"},
        description="Tests for direct prompt injection",
        attack_primitive=AttackPrimitive.INJECTION,
    ),
    Probe(
        id="atomic_context_containment",
        name="Context Containment",
        version="1.0",
        failure_category=FailureCategory.ATOMIC_INJECTION,
        severity=Severity.MEDIUM,
        taxonomy_tags={"owasp": "LLM01"},
        description="Tests for context containment attacks",
        attack_primitive=AttackPrimitive.INJECTION,
    ),
    Probe(
        id="atomic_privilege_escalation",
        name="Privilege Escalation",
        version="1.0",
        failure_category=FailureCategory.TRUST_BOUNDARY_BYPASS,
        severity=Severity.CRITICAL,
        taxonomy_tags={"owasp": "LLM06"},
        description="Tests for privilege escalation via tools",
        attack_primitive=AttackPrimitive.ESCALATION,
    ),
    Probe(
        id="atomic_data_exfiltration",
        name="Data Exfiltration",
        version="1.0",
        failure_category=FailureCategory.ATOMIC_INJECTION,
        severity=Severity.CRITICAL,
        taxonomy_tags={"owasp": "LLM02"},
        description="Tests for sensitive data extraction",
        attack_primitive=AttackPrimitive.EXFILTRATION,
    ),
    Probe(
        id="atomic_system_prompt_leak",
        name="System Prompt Leakage",
        version="1.0",
        failure_category=FailureCategory.ATOMIC_INJECTION,
        severity=Severity.HIGH,
        taxonomy_tags={"owasp": "LLM07"},
        description="Tests for system prompt extraction",
        attack_primitive=AttackPrimitive.EXFILTRATION,
    ),
    Probe(
        id="drift_template_injection",
        name="Template Injection",
        version="1.0",
        failure_category=FailureCategory.BEHAVIORAL_DRIFT,
        severity=Severity.MEDIUM,
        taxonomy_tags={"owasp": "LLM01"},
        description="Tests for template injection attacks",
        attack_primitive=AttackPrimitive.INJECTION,
    ),
    Probe(
        id="drift_jailbreak",
        name="Gradual Jailbreak",
        version="1.0",
        failure_category=FailureCategory.BEHAVIORAL_DRIFT,
        severity=Severity.HIGH,
        taxonomy_tags={"owasp": "LLM01"},
        description="Tests for gradual jailbreak via repeated prompts",
        attack_primitive=AttackPrimitive.ESCALATION,
    ),
    Probe(
        id="trust_untrusted_input",
        name="Untrusted Input Processing",
        version="1.0",
        failure_category=FailureCategory.TRUST_BOUNDARY_BYPASS,
        severity=Severity.HIGH,
        taxonomy_tags={"owasp": "LLM04"},
        description="Tests for untrusted input handling",
        attack_primitive=AttackPrimitive.INJECTION,
    ),
    Probe(
        id="trust_hallucination",
        name="Hallucinated Facts",
        version="1.0",
        failure_category=FailureCategory.ATOMIC_INJECTION,
        severity=Severity.MEDIUM,
        taxonomy_tags={"owasp": "LLM09"},
        description="Tests for fact hallucination",
        attack_primitive=AttackPrimitive.HALLUCINATION,
    ),
]


def get_builtin_probes() -> list[Probe]:
    """Return all built-in probes."""
    return BUILTIN_PROBES


def get_probes_by_category(category: FailureCategory) -> list[Probe]:
    """Filter probes by category."""
    return [p for p in BUILTIN_PROBES if p.failure_category == category]
