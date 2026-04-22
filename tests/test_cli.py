from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tessera.interfaces.cli.main import app


def test_scan_command_exits_cleanly_without_error_zero_message():
    repo_root = Path(__file__).resolve().parents[1]
    config = repo_root / "examples" / "safe_agent.yaml"
    runner = CliRunner()

    result = runner.invoke(app, ["scan", "--config", str(config), "--format", "json"])

    assert result.exit_code == 0
    assert "Error: 0" not in result.output
    assert "Total findings:" in result.output
