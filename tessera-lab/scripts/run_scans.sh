#!/bin/bash
# TESSERA Lab - Run all attack scenarios with risk assessment
# Runs TESSERA against all topology maps, generates CFPE findings + risk scores

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

echo "=============================================="
echo "TESSERA Lab - Attack Validation Run"
echo "=============================================="
echo ""

# Ensure output directories exist
mkdir -p tessera-lab/scanner-runs/{json,sarif,html}
mkdir -p tessera-lab/reports/{json,sarif,html}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Find TESSERA
TESSERA_CMD="$PROJECT_ROOT/.venv/bin/tessera"
if [ ! -f "$TESSERA_CMD" ]; then
    if command -v tessera &> /dev/null; then
        TESSERA_CMD="tessera"
    else
        echo -e "${RED}Error: TESSERA not found${NC}"
        exit 1
    fi
fi

echo "TESSERA: $TESSERA_CMD"
$TESSERA_CMD version 2>/dev/null || echo "Using TESSERA"
echo ""

# Run scans
echo "=== CFPE Detection (tessera scan) ==="
for topo in tessera-lab/topology-maps/*.yaml; do
    name=$(basename "$topo" .yaml)
    out_json="tessera-lab/scanner-runs/json/${name}.json"

    echo -e "${YELLOW}Scanning:${NC} $name"
    $TESSERA_CMD scan --config "tessera-lab/topology-maps/${name}.yaml" --format json --output "$out_json" 2>/dev/null || true

    count=$(grep -o '"id": "CFPE-[0-9]*"' "$out_json" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${GREEN}CFPE findings: ${count}${NC}"
done

# Run risk assessment
echo ""
echo "=== Risk Assessment (tessera risk) ==="
for topo in tessera-lab/topology-maps/*.yaml; do
    name=$(basename "$topo" .yaml)
    out_risk="tessera-lab/scanner-runs/json/${name}_risk.json"

    echo -e "${YELLOW}Risk:${NC} $name"
    $TESSERA_CMD risk --config "tessera-lab/topology-maps/${name}.yaml" --output "$out_risk" 2>/dev/null || true

    score=$(.venv/bin/python -c "import json; d=json.load(open('$out_risk')); print(d.get('risk_score','?'))" 2>/dev/null)
    level=$(.venv/bin/python -c "import json; d=json.load(open('$out_risk')); print(d.get('risk_level','?'))" 2>/dev/null)
    echo -e "  ${GREEN}Risk: ${score}/10 (${level})${NC}"
done

# Generate comparison report
echo ""
echo "Generating comparison report..."

cat > tessera-lab/reports/COMPARISON.md << 'EOF'
# TESSERA Lab - Attack Comparison Report

## CFPE Detection Summary

| Topology | CFPE-0001 | CFPE-0002 | CFPE-0004 | CFPE-0005 | CFPE-0007 | Total |
|----------|-----------|-----------|-----------|-----------|-----------|-------|
EOF

for json in tessera-lab/scanner-runs/json/*_risk.json; do
    continue
done

for json in tessera-lab/scanner-runs/json/*.json; do
    if [[ "$json" == *"_risk.json" ]]; then continue; fi
    if [ -f "$json" ]; then
        name=$(basename "$json" .json)
        count_0001=$(grep -c "CFPE-0001" "$json" 2>/dev/null || echo 0)
        count_0002=$(grep -c "CFPE-0002" "$json" 2>/dev/null || echo 0)
        count_0004=$(grep -c "CFPE-0004" "$json" 2>/dev/null || echo 0)
        count_0005=$(grep -c "CFPE-0005" "$json" 2>/dev/null || echo 0)
        count_0007=$(grep -c "CFPE-0007" "$json" 2>/dev/null || echo 0)
        total=$(grep -o '"id": "CFPE-[0-9]*"' "$json" 2>/dev/null | wc -l | tr -d ' ')
        echo "| $name | $count_0001 | $count_0002 | $count_0004 | $count_0005 | $count_0007 | $total |" >> tessera-lab/reports/COMPARISON.md
    fi
done

cat >> tessera-lab/reports/COMPARISON.md << 'EOF'

## Risk Assessment Summary

| Topology | Risk Score | Risk Level | Attack Paths | Boundary Violations |
|----------|------------|------------|--------------|---------------------|
EOF

for risk_json in tessera-lab/scanner-runs/json/*_risk.json; do
    if [ -f "$risk_json" ]; then
        name=$(basename "$risk_json" _risk.json)
        score=$(.venv/bin/python -c "import json; print(json.load(open('$risk_json')).get('risk_score','?'))" 2>/dev/null)
        level=$(.venv/bin/python -c "import json; print(json.load(open('$risk_json')).get('risk_level','?'))" 2>/dev/null)
        paths=$(.venv/bin/python -c "import json; print(len(json.load(open('$risk_json')).get('attack_paths',[])))" 2>/dev/null)
        violations=$(.venv/bin/python -c "import json; print(json.load(open('$risk_json')).get('boundary_violations',0))" 2>/dev/null)
        echo "| $name | $score/10 | $level | $paths | $violations |" >> tessera-lab/reports/COMPARISON.md
    fi
done

echo "" >> tessera-lab/reports/COMPARISON.md
echo "Generated at $(date)" >> tessera-lab/reports/COMPARISON.md

echo -e "${GREEN}Done!${NC}"
echo "Report: tessera-lab/reports/COMPARISON.md"