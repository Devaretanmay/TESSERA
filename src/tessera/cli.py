import typer
import yaml
from pathlib import Path
from tessera.topology.loader import TopologyLoader
from tessera.topology.models import TopologyGraph

app = typer.Typer(name="tessera", help="TESSERA - AI Security Testing Platform")


@app.command()
def scan(
    config: Path = typer.Option(
        ..., exists=True, file_okay=True, dir_okay=False, help="Topology YAML config"
    ),
    tier: int = typer.Option(1, help="Scan tier (1/2/3)"),
    severity_threshold: str = typer.Option("high", help="Blocking threshold for tier 2"),
    target_provider: str = typer.Option(None, help="Target provider (ollama/openai/anthropic)"),
    target_url: str = typer.Option(None, help="Target URL (e.g., http://localhost:11434)"),
    target_model: str = typer.Option(None, help="Model name"),
):
    from tessera.db.persistence import Persistence
    from tessera.classifier.rule_based import CompoundClassifier
    from tessera.api.scan_executor import ScanExecutor

    typer.echo(f"Running tier {tier} scan on {config}")
    loader = TopologyLoader(config)
    graph = loader.load()
    typer.echo(f"Loaded topology: {graph.system} v{graph.version}")
    typer.echo(f"  Nodes: {len(graph.nodes)}, Edges: {len(graph.edges)}")

    attack_surface = graph.attack_surface()
    typer.echo(f"  Attack surface: {len(attack_surface)} untrusted edges")

    # Initialize target adapter if provided
    target_adapter = None
    if target_provider:
        from tessera.swarm.adapters import create_backbone, BackboneAdapter

        target_adapter: BackboneAdapter | None = create_backbone(
            target_provider,
            base_url=target_url or "http://localhost:11434",
            model=target_model or "",
        )
        if target_adapter:
            typer.echo(
                f"  Target: {target_provider}/{target_model or target_adapter.get_model_name()} @ {target_url or 'default'}"
            )
        else:
            typer.echo(
                f"  Warning: Could not create adapter for {target_provider}, running simulation only"
            )

    # Execute scan with classifier
    db = Persistence()
    classifier = CompoundClassifier()
    executor = ScanExecutor(
        graph=graph, db=db, classifier=classifier, target=target_adapter, tier=tier
    )
    result = executor.execute()

    # Show results
    typer.echo(f"\n✓ Scan completed: {result['scan_id'][:8]}")
    typer.echo(f"  Findings: {result['findings_count']}")
    if result["severity_counts"]:
        for sev, count in result["severity_counts"].items():
            if count > 0:
                typer.echo(f"    {sev.upper()}: {count}")

    # Show token usage
    if result.get("token_usage"):
        tokens = result["token_usage"]
        typer.echo(
            f"  Tokens: {tokens.get('total', 0)} (in: {tokens.get('input', 0)}, out: {tokens.get('output', 0)})"
        )
        typer.echo(f"  Est. cost: {tokens.get('cost_estimate', '$0.0000')}")


@app.command()
def discover(
    source: Path = typer.Option(..., exists=True, help="Source: OpenAPI/YAML file"),
    format: str = typer.Option("openapi", help="Format: openapi, langgraph"),
    output: Path = typer.Option(None, help="Output topology YAML file"),
):
    from tessera.topology.auto_discover import OpenAPITopologyBuilder, LangGraphTopologyBuilder
    import yaml

    typer.echo(f"Auto-discovering topology from {source}")

    if format == "openapi":
        builder = OpenAPITopologyBuilder(source)
        topo = builder.to_topology()
    else:
        with open(source) as f:
            data = yaml.safe_load(f)
        builder = LangGraphTopologyBuilder(data)
        topo = builder.to_topology()

    typer.echo(f"Discovered: {topo['system']} v{topo['version']}")
    typer.echo(f"  Nodes: {len(topo.get('nodes', []))}")
    typer.echo(f"  Edges: {len(topo.get('edges', []))}")

    if output:
        topo_yaml = yaml.dump(topo, default_flow_style=False)
        with open(output, "w") as f:
            f.write(topo_yaml)
        typer.echo(f"✓ Saved to {output}")

    return topo


@app.command()
def topology(
    config: Path = typer.Option(..., exists=True, help="Topology YAML config"),
    visualize: bool = typer.Option(False, help="Visualize graph"),
    validate: bool = typer.Option(False, help="Validate config"),
):
    loader = TopologyLoader(config)
    if validate:
        valid, errors = loader.validate()
        if valid:
            typer.echo("✓ Valid topology")
        else:
            for err in errors:
                typer.echo(f"✗ {err}", err=True)
        return

    graph = loader.load()
    typer.echo(f"System: {graph.system} v{graph.version}")
    typer.echo(f"Nodes: {len(graph.nodes)}")
    typer.echo(f"Edges: {len(graph.edges)}")

    if visualize:
        for node_id, node in graph.nodes.items():
            edges_from = graph.get_edges_from(node_id)
            for edge in edges_from:
                typer.echo(f"  {node_id} --[{edge.flow.value}]--> {edge.to_node}")
        surface = graph.attack_surface()
        if surface:
            typer.echo("\nAttack Surface (untrusted edges):")
            for s in surface:
                typer.echo(f"  ⚠ {s['edge']} ({s['flow'].value})")


@app.command()
def findings(
    scan_id: str = typer.Option(None, help="Scan ID (omit for latest scan)"),
    format: str = typer.Option(None, help="Export format (json/sarif/jsonl)"),
    output: Path = typer.Option(None, help="Output file (prints to stdout if omitted)"),
    list_all: bool = typer.Option(False, help="List all findings for scan"),
):
    from tessera.db.persistence import Persistence
    from tessera.api.export import FindingExporter
    from tessera.findings.models import Finding, FindingSeverity, FailureType, AttackTraceEntry

    db = Persistence()

    # If no scan_id provided, get latest scan
    if not scan_id:
        scans = db.list_scans(limit=1)
        if not scans:
            typer.echo("No scans found. Run a scan first.", err=True)
            raise typer.Exit(1)
        scan_id = scans[0].scan_id
        typer.echo(f"Using latest scan: {scan_id[:8]}")

    # Get findings from DB
    findings_records = db.get_findings(scan_id)

    if not findings_records:
        typer.echo(f"No findings for scan {scan_id[:8]}")
        return

    # Only echo success message if not printing structured data to stdout
    if not (format and not output):
        typer.echo(f"✓ {len(findings_records)} findings for scan {scan_id[:8]}")

    # Convert to Finding model
    findings_list = [
        Finding(
            finding_id=f.finding_id,
            scan_id=f.scan_id,
            timestamp=f.timestamp,
            severity=FindingSeverity(f.severity),
            failure_type=FailureType(f.failure_type),
            topology_path=f.topology_path,
            attack_trace=[AttackTraceEntry(**t) for t in f.attack_trace],
            evidence=f.evidence,
            remediation=f.remediation,
            confidence=f.confidence,
        )
        for f in findings_records
    ]

    if output or format:
        fmt = format or "json"
        if output:
            if fmt == "sarif":
                FindingExporter.to_sarif(findings_list, output)
            elif fmt == "jsonl":
                FindingExporter.to_jsonl(findings_list, output)
            else:
                FindingExporter.to_json(findings_list, output)
            typer.echo(f"  Exported to {output}")
        else:
            import json

            if fmt == "sarif":
                typer.echo(json.dumps(FindingExporter.generate_sarif(findings_list), indent=2))
            elif fmt == "jsonl":
                for f in findings_list:
                    typer.echo(json.dumps(f.to_dict()))
            else:  # json
                typer.echo(json.dumps([f.to_dict() for f in findings_list], indent=2))
    else:
        # Print summary to stdout
        for i, f in enumerate(findings_list, 1):
            typer.echo(f"  {i}. [{f.severity.value.upper()}] {f.failure_type.value}")
            typer.echo(f"     Path: {' → '.join(f.topology_path)}")
            typer.echo(f"     Confidence: {f.confidence:.2f}")


@app.command()
def scans(
    list_all: bool = typer.Option(True, help="List recent scans"),
    limit: int = typer.Option(10, help="Number of scans to show"),
):
    from tessera.db.persistence import Persistence

    db = Persistence()
    scan_records = db.list_scans(limit=limit)

    if not scan_records:
        typer.echo("No scans found")
        return

    typer.echo(f"Recent scans ({len(scan_records)}):")
    for scan in scan_records:
        status_icon = "✓" if scan.status == "completed" else "⏳"
        typer.echo(
            f"  {status_icon} {scan.scan_id[:8]} | {scan.system} | tier {scan.tier} | {scan.findings_count} findings | {scan.created_at[:19]}"
        )


@app.command()
def probes(
    list_all: bool = typer.Option(False, help="List all probes"),
    category: str = typer.Option(None, help="Filter by category"),
    import_garak: str = typer.Option(None, help="Import probes from GARAK directory"),
):
    from tessera.probes.models import ProbeRegistry, FailureCategory, AttackPrimitive

    if import_garak:
        from tessera.probes.garak_import import import_garak as do_import

        result = do_import(import_garak)
        typer.echo(f"Found {result['total_found']} GARAK probes")
        typer.echo(f"Imported {result['imported']} probes")
        return

    # Show probe registry (including built-ins)
    from tessera.probes.builtin import get_builtin_probes

    registry = ProbeRegistry()
    for probe in get_builtin_probes():
        registry.register(probe)

    probes = list(registry.probes.values())

    if not probes:
        typer.echo("Probe registry is empty")
        typer.echo("\nBuilt-in failure categories:")
        for cat in FailureCategory:
            typer.echo(f"  • {cat.value}")
        typer.echo(f"\nAttack primitives:")
        for prim in AttackPrimitive:
            typer.echo(f"  - {prim.value}")
        return

    typer.echo(f"Probe registry ({len(probes)} probes):")
    if category:
        probes = [p for p in probes if p.category == category]
        typer.echo(f"  Filtered by: {category}")

    for probe in probes:
        typer.echo(f"  • {probe.name} [{probe.failure_category.value}]")


@app.command()
def server(
    port: int = typer.Option(8000, help="Port to run server on"),
    host: str = typer.Option("127.0.0.1", help="Host to bind to"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
):
    """Start TESSERA API server."""
    import uvicorn

    typer.echo(f"Starting TESSERA API server on {host}:{port}...")
    uvicorn.run("tessera.api.server:app", host=host, port=port, reload=reload)


@app.command()
def fingerprint(
    calibrate: str = typer.Option(None, help="Calibrate with sample queries file"),
    detect: str = typer.Option(None, help="Detect drift against baseline"),
    baseline: str = typer.Option(None, help="Baseline file for drift detection"),
    threshold: float = typer.Option(0.15, help="Drift threshold (default: 0.15)"),
    webhook: str = typer.Option(None, help="Webhook URL for drift alerts"),
):
    if calibrate:
        typer.echo(f"Calibrating fingerprint from {calibrate}")
        from tessera.fingerprint.engine import FingerprintEngine
        import asyncio

        with open(calibrate) as f:
            queries = [line.strip() for line in f if line.strip()]

        engine = FingerprintEngine()
        asyncio.run(
            engine.create_baseline(
                {
                    "benign_standard": queries,
                    "benign_edge": queries[: len(queries) // 2] if len(queries) > 1 else queries,
                }
            )
        )

        baseline_path = "/tmp/tessera_baseline.json"
        engine.save_baseline(baseline_path)
        typer.echo(f"✓ Baseline saved to {baseline_path}")
        return

    if detect:
        if not baseline:
            typer.echo("--baseline required for drift detection", err=True)
            return

        typer.echo(f"Checking drift for {detect}")
        from tessera.fingerprint.engine import FingerprintEngine
        import asyncio

        engine = FingerprintEngine()
        engine.load_baseline(baseline)

        with open(detect) as f:
            responses = [line.strip() for line in f if line.strip()]

        result = asyncio.run(engine.check_drift(responses, webhook_url=webhook))

        if webhook and result.get("is_drift"):
            typer.echo(f"→ Alert sent to {webhook}")

        score_key = "drift_score" if "drift_score" in result else "mmd_score"
        score = result.get(score_key, "N/A")
        score_str = f"{score:.3f}" if isinstance(score, float) else str(score)

        if result.get("is_drift"):
            typer.echo(f"⚠️  DRIFT DETECTED (score: {score_str})")
        else:
            typer.echo(f"✓ No drift (score: {score_str})")

        typer.echo(f"Threshold: {threshold}")
        return

    typer.echo("Fingerprint commands: --calibrate, --detect")


@app.command()
def auth(
    action: str = typer.Argument(..., help="Action: create-key, list-keys, revoke"),
    name: str = typer.Option(None, help="Name for API key"),
    key_id: str = typer.Option(None, help="Key ID to revoke"),
    tenant: str = typer.Option("default", help="Tenant ID"),
    permissions: str = typer.Option("scan,view", help="Comma-separated permissions"),
):
    from tessera.enterprise.auth import get_auth_store
    from tessera.enterprise.models import Role, Permission

    store = get_auth_store()

    if action == "create-key":
        if not name:
            typer.echo("--name required for create-key", err=True)
            return

        perms = [Permission(p.strip()) for p in permissions.split(",")]
        user = store.create_user(tenant, "CLI User", "cli@tessera", Role.API_USER)
        key, raw = store.create_api_key(tenant, user.id, name, perms, expires_days=90)

        typer.echo(f"API Key created for tenant {tenant}:")
        typer.echo(f"  Key ID: {key.id}")
        typer.echo(f"  Raw Key: {raw}")
        typer.echo(f"  ⚠️  Save this key - it cannot be shown again!")
        return

    if action == "list-keys":
        keys = store.list_keys(tenant)
        if not keys:
            typer.echo(f"No API keys for tenant {tenant}")
            return
        typer.echo(f"API Keys for tenant {tenant}:")
        for k in keys:
            typer.echo(f"  {k.id}: {k.name} (expires: {k.expires_at or 'never'})")
        return

    if action == "revoke":
        if not key_id:
            typer.echo("--key-id required for revoke", err=True)
            return

        if store.revoke_key(key_id):
            typer.echo(f"Key {key_id} revoked")
        else:
            typer.echo(f"Key {key_id} not found", err=True)
        return

    typer.echo("auth actions: create-key, list-keys, revoke")


@app.command()
def swarm(
    topology_file: str = typer.Option(..., help="Path to topology YAML"),
    iterations: int = typer.Option(10, help="Max iterations per agent"),
    agent_count: int = typer.Option(5, help="Number of agents"),
    backbone: str = typer.Option("ollama", help="LLM backbone (ollama/openai/anthropic)"),
):
    typer.echo(f"Running adaptive swarm with {agent_count} agents, {iterations} iterations")

    from tessera.swarm.engine import SwarmConfig, SwarmCoordinator
    from tessera.swarm.adapters import create_backbone
    import asyncio

    with open(topology_file) as f:
        topo = yaml.safe_load(f)

    paths = topo.get("paths", [["input", "processor", "output"]])

    probes = [
        {"name": p} for p in ["injection_probe", "escalation_probe", "exfil_probe", "fuzz_probe"]
    ] * 10

    adapter = create_backbone(backbone)

    if adapter:
        est_cost = adapter.get_cost_estimate(
            f"test prompt for {iterations * agent_count} iterations"
        )
        cost_display = (
            f"${est_cost * iterations * agent_count * 0.001:.2f}"
            if est_cost > 0
            else "$0.00 (local)"
        )
        typer.echo(f"  Estimated cost: {cost_display}")

    config = SwarmConfig(agent_count=agent_count, max_iterations=iterations)
    coordinator = SwarmCoordinator(config, backbone=adapter)

    result = asyncio.run(coordinator.run(paths, probes))

    typer.echo(
        f"✓ Swarm complete: {result['total_iterations']} iterations, {result['discoveries']} discoveries"
    )

    stats = result.get("evolution_stats", {})
    typer.echo(f"Evolution generation: {stats.get('generation', 'N/A')}")

    for role, primitives in result.get("best_primitives", {}).items():
        typer.echo(f"  {role}: {primitives}")


@app.command()
def siem(
    provider: str = typer.Option(..., help="SIEM provider (splunk/datadog)"),
    findings_file: str = typer.Option(..., help="JSON file with findings"),
    url: str = typer.Option(None, help="Splunk HEC URL (for splunk)"),
    token: str = typer.Option(None, help="API token"),
    api_key: str = typer.Option(None, help="Datadog API key (for datadog)"),
    index: str = typer.Option("main", help="Splunk index"),
):
    import asyncio
    import json
    from tessera.siem.connectors import SIEMProvider, export_findings_to_siem

    with open(findings_file) as f:
        findings = json.load(f)

    provider_enum = SIEMProvider(provider.lower())
    kwargs = {}
    if provider.lower() == "splunk":
        if not url or not token:
            typer.echo("--url and --token required for splunk", err=True)
            return
        kwargs = {"url": url, "token": token, "index": index}
    elif provider.lower() == "datadog":
        if not api_key:
            typer.echo("--api-key required for datadog", err=True)
            return
        kwargs = {"api_key": api_key}

    result = asyncio.run(export_findings_to_siem(findings, provider_enum, **kwargs))
    typer.echo(f"✓ SIEM export: {result['success']} sent, {result['failed']} failed")


def _build_graph(topo):
    from tessera.classifier.gnn.data import (
        TopologyGraph,
        NodeType,
        EdgeType,
        TrustLevel,
        GraphNode,
        GraphEdge,
    )

    graph = TopologyGraph()
    for node_data in topo.get("nodes", []):
        graph.add_node(
            GraphNode(
                node_data.get("id", "unknown"),
                NodeType(node_data.get("type", "llm")),
                TrustLevel(node_data.get("trust_boundary", "trusted")),
            )
        )
    for edge in topo.get("edges", []):
        graph.add_edge(
            GraphEdge(
                edge.get("from", "unknown"),
                edge.get("to", "unknown"),
                EdgeType(edge.get("flow", "prompt")),
                TrustLevel(edge.get("trust_level", "trusted")),
            )
        )
    return graph


@app.command()
def gnn(
    action: str = typer.Argument(..., help="Action: train, predict, info"),
    topology_file: str = typer.Option(None, help="Topology file for prediction"),
    epochs: int = typer.Option(100, help="Training epochs"),
    label: int = typer.Option(0, help="Label for training (0=safe, 1=atomic, 2=chain, 3=exfil)"),
):
    if action == "info":
        typer.echo("GNN Classifier:")
        typer.echo(
            "  GraphSAGE architecture, 4-class: safe, atomic_injection, chain_exploitation, exfiltration"
        )
        typer.echo("  Run 'tessera gnn train' to train")
        return

    if not topology_file:
        typer.echo("--topology-file required", err=True)
        return

    import yaml

    with open(topology_file) as f:
        topo = yaml.safe_load(f)

    from tessera.classifier.gnn.pipeline import create_pipeline

    pipeline = create_pipeline()
    graph = _build_graph(topo)

    if action == "train":
        from tessera.classifier.gnn.pipeline import TrainingSample

        pipeline.add_sample(TrainingSample(graph=graph, label=label))
        result = pipeline.train(epochs=epochs)
        typer.echo(
            f"Training complete: {result.get('final_loss', 0.0):.4f} loss, {result.get('samples_trained', 0)} samples"
        )

    elif action == "predict":
        result = pipeline.predict(graph)
        for pred in result["predictions"]:
            typer.echo(f"  {pred['class']} ({pred['confidence']:.2f})")

    elif action == "train-synthetic":
        from tessera.classifier.gnn.training_data import create_training_dataset

        typer.echo("Generating synthetic data...")
        train_samples, test_samples = create_training_dataset()
        for s in train_samples:
            pipeline.add_sample(graph=s["graph"], label=s["label"])
        result = pipeline.train(epochs=epochs)
        typer.echo(f"Training complete: {result.get('final_loss', 0.0):.4f} loss")
        correct = sum(
            1
            for s in test_samples
            if pipeline.predict(s["graph"])["predictions"][0]["class_index"] == s["label"]
        )
        typer.echo(f"  Accuracy: {correct / len(test_samples) * 100:.1f}%")

    else:
        typer.echo("Actions: train, predict, train-synthetic, info")


@app.command()
def marketplace(
    action: str = typer.Argument(..., help="Action: publish, search, install, list, plugins"),
    query: str = typer.Argument(None, help="Search query (for search/install)"),
    name: str = typer.Option(None, help="Package name"),
    version: str = typer.Option("latest", help="Package version"),
    category: str = typer.Option(None, help="Category filter"),
    registry_path: str = typer.Option("/tmp/tessera_registry", help="Registry path"),
):
    from tessera.marketplace.registry import get_registry, create_probe_package
    from tessera.marketplace.plugins import get_plugin_registry

    reg = get_registry()

    if action == "list":
        packages = reg.list_all()
        typer.echo(f"Registered packages ({len(packages)}):")
        for p in packages:
            typer.echo(f"  {p['name']}:{p['version']} ({p['category']}) by {p['author']}")
        return

    if action == "search":
        search_query = query or name or ""
        results = reg.search(query=search_query, category=category)
        typer.echo(f"Search results ({len(results)}):")
        for p in results:
            typer.echo(f"  {p.name}:{p.version} - {p.description[:50]}")
        return

    if action == "publish":
        if not name:
            typer.echo("--name required for publish", err=True)
            return

        pkg = create_probe_package(
            name=name,
            version=version if version != "latest" else "1.0.0",
            description="Custom probe package",
            author="user",
            category=category or "custom",
            probes=[{"name": f"{name}_probe", "type": "injection"}],
        )
        key = reg.publish(pkg)
        typer.echo(f"✓ Published {key}")
        return

    if action == "install":
        pkg_name = query or name
        if not pkg_name:
            typer.echo("Package name required for install", err=True)
            return

        pkg = reg.install(pkg_name, version)
        if pkg:
            typer.echo(f"✓ Installed {pkg.name}:{pkg.version}")
            typer.echo(f"  Probes: {len(pkg.probes)}")
        else:
            typer.echo(f"Package {pkg_name}:{version} not found", err=True)
        return

    if action == "plugins":
        plug_reg = get_plugin_registry()
        plugins = plug_reg.list()
        typer.echo(f"Loaded plugins ({len(plugins)}):")
        for p in plugins:
            typer.echo(f"  {p['name']}:{p['version']}")
        return

    typer.echo("marketplace actions: publish, search, install, list, plugins")


if __name__ == "__main__":
    app()
