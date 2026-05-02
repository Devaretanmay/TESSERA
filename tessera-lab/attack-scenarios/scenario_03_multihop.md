# Attack Scenario 3: Multi-hop Attack Chain
## CFPE-0005

### Description
An attacker chains multiple vulnerabilities across components, creating a complex attack path that spans 4+ hops from user input to sensitive data exfiltration.

### Attack Vector
1. User input → Web API (untrusted boundary)
2. Web API → LLM (context injection)
3. LLM → RAG (knowledge retrieval)
4. RAG → Tool (tool chaining)
5. Tool → Database (data access)

### Path Example
```
user_input -> web_api -> chat_llm -> rag_corpus -> search_tool -> database
```

### Expected TESSERA Detection
- CFPE-0005: Multi-hop attack chain (4+ hops)
- CFPE-0003: External to Database
- CFPE-0007: Sensitive data exfiltration

### Detection Evidence
```json
{
  "id": "CFPE-0005",
  "severity": "high",
  "description": "Multi-hop attack chain detected (5 hops): user_input -> web_api -> chat_llm -> rag_corpus -> search_tool -> database"
}
```

### Mitigation
1. Break long chains with validation points
2. Implement multiple security layers
3. Monitor chain interactions
4. Add circuit breakers between hops
5. Log and alert on multi-hop flows