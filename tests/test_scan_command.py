"""Tests for the scan command - verifies full scan orchestration flow."""
import pytest
import tempfile
import os
from pathlib import Path

from tessera.classifier.rule_based import CompoundClassifier
from tessera.db.persistence import Persistence, ScanRecord, FindingRecord
from tessera.topology.loader import TopologyLoader
from tessera.api.scan_executor import ScanExecutor


@pytest.fixture
def topology_file():
    """Create a test topology YAML file."""
    yaml_content = """
name: "Test RAG Bot"
description: "Test RAG system"
version: "1.0"

nodes:
  - id: "llm_main"
    type: "model"
    trust_boundary: "trusted"
    model: "gpt-4"

  - id: "rag_corpus"
    type: "rag_corpus"
    trust_boundary: "trusted"

  - id: "tool_db"
    type: "tool"
    trust_boundary: "partially_trusted"

edges:
  - from: "llm_main"
    to: "rag_corpus"
    flow: "retrieval"
    trust_level: "trusted"

  - from: "llm_main"
    to: "tool_db"
    flow: "tool_call"
    trust_level: "untrusted"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        f.flush()
        yield Path(f.name)
    os.unlink(f.name)


@pytest.fixture
def temp_db():
    """Create a temporary database."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    if db_path.exists():
        os.unlink(db_path)


def test_scan_executor_runs_classifier_and_persists(temp_db, topology_file):
    """CRITICAL: Scan should execute classifier against attack paths and persist findings.
    
    This is the core flow that was missing:
    1. Load topology
    2. Run classifier on simulated adversarial traces
    3. Persist scan record to DB
    4. Persist findings records to DB
    5. Verify can retrieve them
    """
    # Load topology
    loader = TopologyLoader(topology_file)
    graph = loader.load()
    
    # Create scan executor
    db = Persistence(db_path=temp_db)
    classifier = CompoundClassifier()
    executor = ScanExecutor(graph=graph, db=db, classifier=classifier)
    
    # Execute scan - this should run classifier and persist results
    result = executor.execute()
    
    # Verify scan was persisted
    assert result["scan_id"] is not None
    assert result["status"] == "completed"
    
    # Retrieve scan from DB
    scan_record = db.get_scan(result["scan_id"])
    assert scan_record is not None
    assert scan_record.system == "Test RAG Bot"  # Name field works
    assert scan_record.status == "completed"
    
    # Verify findings were persisted
    findings = db.get_findings(result["scan_id"])
    assert len(findings) > 0  # At least some findings generated
    
    # Verify finding structure
    finding = findings[0]
    assert finding.scan_id == result["scan_id"]
    assert finding.severity in ["critical", "high", "medium", "low", "info"]
    assert len(finding.topology_path) > 0


def test_scan_executor_detects_compound_failures(temp_db, topology_file):
    """Scan should detect compound failure patterns and report them correctly."""
    loader = TopologyLoader(topology_file)
    graph = loader.load()
    
    db = Persistence(db_path=temp_db)
    classifier = CompoundClassifier()
    executor = ScanExecutor(graph=graph, db=db, classifier=classifier)
    
    result = executor.execute()
    
    # Findings should include compound failure detections
    findings = db.get_findings(result["scan_id"])
    
    # At least one finding should be compound_chain type
    compound_findings = [f for f in findings if f.failure_type == "compound_chain"]
    assert len(compound_findings) > 0, "Scan should detect compound failures"


def test_scan_executor_persists_severity_counts(temp_db, topology_file):
    """Scan record should include accurate severity counts."""
    loader = TopologyLoader(topology_file)
    graph = loader.load()
    
    db = Persistence(db_path=temp_db)
    classifier = CompoundClassifier()
    executor = ScanExecutor(graph=graph, db=db, classifier=classifier)
    
    result = executor.execute()
    
    # Retrieve scan
    scan = db.get_scan(result["scan_id"])
    
    # Should have severity counts
    assert scan.severity_counts is not None
    assert isinstance(scan.severity_counts, dict)
    assert scan.findings_count > 0
    assert scan.findings_count == len(db.get_findings(result["scan_id"]))
