"""
CLI entry point for TESSERA.
"""

from pathlib import Path
import json
import os

import typer

from tessera.core.topology.loader import ValidationError, Loader
from tessera.engine.scanner import Tessera, OutputFormat
from tessera.infra.logging_utils import configure_logging

configure_logging(level=os.getenv("TESSERA_LOG_LEVEL", "WARNING"), json_logs=False)
app = typer.Typer(help="TESSERA - AI Security Scanner")


@app.command()
def scan(
    config: Path = typer.Option(..., exists=True, help="Topology YAML file"),
    format: str = typer.Option("text", help="Output format: text, json, sarif, html"),
    llm: bool = typer.Option(False, help="Enable LLM analysis"),
    output: Path | None = typer.Option(None, help="Output file (optional)"),
):
    """Scan a topology file for security vulnerabilities."""
    try:
        scanner = Tessera()

        # Enable LLM if requested
        if llm:
            scanner.enable_llm()

        # Run scan
        format_enum = OutputFormat(format.lower())
        result = scanner.scan(str(config), format_enum, llm_enabled=llm)

        # Output
        if output:
            if format_enum in {OutputFormat.JSON, OutputFormat.SARIF}:
                with output.open("w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2)
                typer.echo(f"Results written to {output}")
            else:
                with output.open("w", encoding="utf-8") as f:
                    f.write(result)
                typer.echo(f"Results written to {output}")
        else:
            if format_enum in {OutputFormat.JSON, OutputFormat.SARIF}:
                typer.echo(json.dumps(result, indent=2))
            else:
                typer.echo(result)

        # Summary
        if format_enum == OutputFormat.JSON and isinstance(result, dict):
            summary = result.get("summary", {})
            typer.echo(f"\nTotal findings: {summary.get('total', 0)}")

        return

    except typer.Exit:
        raise
    except (ValidationError, ValueError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def topology(
    config: Path = typer.Option(..., exists=True, help="Topology YAML file"),
    validate: bool = typer.Option(False, help="Validate only"),
):
    """Show topology information."""
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
def list_rules():
    """List all detection rules."""
    from tessera.core.detection.patterns import RULES

    typer.echo("CFPE Detection Rules:")
    typer.echo("=" * 50)

    for rule in RULES:
        typer.echo(f"\n{rule.id}: {rule.name}")
        if hasattr(rule, "remediation"):
            typer.echo(f"  Remediation: {rule.remediation.get('summary', 'N/A')}")


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID (e.g., CFPE-0001)"),
):
    """Explain a detection rule."""
    from tessera.core.detection.patterns import RULES

    for rule in RULES:
        if rule.id == rule_id:
            typer.echo(f"{rule.id}: {rule.name}")
            typer.echo(f"Applies to: {', '.join(rule.applies_to)}")

            if hasattr(rule, "remediation"):
                rem = rule.remediation
                typer.echo("\nRemediation:")
                typer.echo(f"  Summary: {rem.get('summary', 'N/A')}")
                typer.echo(f"  How to fix:\n{rem.get('how_to_fix', 'N/A')}")
                refs = rem.get("references", [])
                if refs:
                    typer.echo(f"  References: {', '.join(refs)}")
            return

    typer.echo(f"Rule {rule_id} not found", err=True)
    raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    from tessera import __version__

    typer.echo(f"TESSERA v{__version__}")


@app.command()
def risk(
    config: Path = typer.Option(..., exists=True, help="Topology YAML file"),
    output: Path | None = typer.Option(None, help="Output file (optional)"),
):
    """Assess risk and generate attack paths for a topology."""
    from tessera.core.risk import assess_risk

    try:
        loader = Loader()
        graph = loader.load(str(config))

        assessment = assess_risk(graph, config.stem)

        if output:
            with output.open("w", encoding="utf-8") as f:
                json.dump(assessment.to_dict(), f, indent=2)
            typer.echo(f"Risk assessment written to {output}")
        else:
            typer.echo(assessment.to_explanation())

    except ValidationError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
