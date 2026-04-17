"""
CLI entry point.
"""

from pathlib import Path
import typer
import json

from tessera.core.topology.loader import ValidationError, Loader
from tessera.engine.scanner import Scanner, PipelineError
from tessera.infra.db.repository import Repository, ScanRecord

app = typer.Typer(help="TESSERA - AI Security Scanner")


@app.command()
def scan(
    config: Path = typer.Option(..., exists=True, help="Topology YAML"),
    tier: str = typer.Option("2", help="Scan tier (1=gate, 2=full, 3=nightly)"),
    system: str = typer.Option("tessera", help="System name"),
):
    try:
        repo = Repository()
        scanner = Scanner(repo)
        scan_id, findings = scanner.run(str(config), tier, system)

        typer.echo(f"Scan {scan_id[:8]} completed")
        typer.echo(f"Findings: {len(findings)}")

        if findings:
            typer.echo("\nResults:")
            for f in findings:
                typer.echo(f"  [{f.severity.value.upper()}] {f.failure_type.value}")

        raise typer.Exit(0)

    except (ValidationError, PipelineError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def topology(
    config: Path = typer.Option(..., exists=True, help="Topology YAML"),
    validate: bool = typer.Option(False, help="Validate only"),
):
    loader = Loader()

    try:
        graph = loader.load(str(config))
        typer.echo(f"System: {graph.system} v{graph.version}")
        typer.echo(f"Nodes: {len(graph.nodes)}")
        typer.echo(f"Edges: {len(graph.edges)}")

        if validate:
            typer.echo("\nValidation: OK")

    except ValidationError as e:
        typer.echo(f"Validation failed: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def findings(
    scan_id: str = typer.Option(None, help="Scan ID (latest if omitted)"),
    format: str = typer.Option("json", help="Output format (json/text)"),
):
    repo = Repository()

    if not scan_id:
        scans = repo.list_scans(limit=1)
        if not scans:
            typer.echo("No scans found", err=True)
            raise typer.Exit(1)
        scan_id = scans[0].scan_id
    else:
        scan_id = repo.resolve_scan_id(scan_id)

    findings_list = repo.get_findings(scan_id)

    if not findings_list:
        typer.echo(f"No findings for scan {scan_id[:8]}")
        return

    if format == "text":
        typer.echo(f"Findings for {scan_id[:8]} ({len(findings_list)}):")
        for f in findings_list:
            typer.echo(f"  [{f.severity.value.upper()}] {f.failure_type.value}")
    else:
        typer.echo(json.dumps([f.to_dict() for f in findings_list], indent=2))


@app.command()
def scans(
    limit: int = typer.Option(10, help="Number of scans to show"),
):
    repo = Repository()
    scan_list = repo.list_scans(limit=limit)

    if not scan_list:
        typer.echo("No scans found")
        return

    typer.echo(f"Recent scans ({len(scan_list)}):")
    for s in scan_list:
        typer.echo(f"  {s.scan_id[:8]} | {s.system} | tier {s.tier} | {s.created_at[:10]}")


@app.command()
def server(
    host: str = typer.Option("127.0.0.1", help="Host"),
    port: int = typer.Option(8000, help="Port"),
):
    import uvicorn
    from tessera.infra.api.server import app

    typer.echo(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    app()
