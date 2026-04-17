"""
CLI entry point - orchestration only.
No business logic.
"""

import sys
from pathlib import Path
import typer

from tessera.core.topology.loader import ValidationError
from tessera.engine.scanner import Scanner, PipelineError
from tessera.infra.db.repository import Repository

app = typer.Typer(help="TESSERA - AI Security Scanner")


@app.command()
def scan(
    config: Path = typer.Option(..., exists=True, help="Topology YAML"),
    tier: str = typer.Option("2", help="Scan tier"),
    system: str = typer.Option("tessera", help="System name"),
):
    """Run security scan."""
    try:
        repo = Repository()
        scanner = Scanner(repo)

        scan_id, findings = scanner.run(str(config), tier, system)

        typer.echo(f"Scan {scan_id} completed")
        typer.echo(f"Findings: {len(findings)}")

        for f in findings:
            typer.echo(f"  [{f.severity.value.upper()}] {f.failure_type.value}")

        raise typer.Exit(0)

    except (ValidationError, PipelineError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def server(
    host: str = typer.Option("0.0.0.0", help="Host"),
    port: int = typer.Option(8000, help="Port"),
):
    """Start API server."""
    import uvicorn
    from tessera.infra.api.server import app

    typer.echo(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    app()
