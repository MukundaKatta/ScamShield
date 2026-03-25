"""CLI entry-point: scamshield check / scamshield scan."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from scamshield.core import BulkScanner, ScamDetector

app = typer.Typer(
    name="scamshield",
    help="ScamShield — Fraud and scam detection engine.",
    add_completion=False,
)
console = Console()


def _color_for_level(level: str) -> str:
    return {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(
        level, "white"
    )


@app.command()
def check(
    message: str = typer.Argument(..., help="The text message to analyze."),
    sensitivity: float = typer.Option(0.5, "--sensitivity", "-s", help="0.0-1.0"),
) -> None:
    """Analyze a single message for scam indicators."""
    from scamshield.config import DetectionConfig

    config = DetectionConfig(sensitivity=sensitivity)
    detector = ScamDetector(config=config)
    report = detector.analyze(message)

    color = _color_for_level(report.risk_score.level)
    console.print(f"\n[bold]ScamShield Analysis[/bold]")
    console.print(f"Score: [{color}]{report.risk_score.total}/100[/{color}]  "
                  f"Level: [{color}]{report.risk_score.level}[/{color}]")
    console.print(f"Scam type: {report.scam_type}")
    if report.flagged_phrases:
        console.print(f"Flagged: {', '.join(report.flagged_phrases)}")
    console.print(f"\n{report.explanation}\n")


@app.command()
def scan(
    csv_path: Path = typer.Argument(..., help="Path to CSV file with messages."),
    column: str = typer.Option("message", "--column", "-c", help="Column name."),
    sensitivity: float = typer.Option(0.5, "--sensitivity", "-s"),
) -> None:
    """Bulk-scan messages from a CSV file."""
    from scamshield.config import DetectionConfig

    config = DetectionConfig(sensitivity=sensitivity)
    scanner = BulkScanner(config=config)
    reports = scanner.scan_csv(str(csv_path), column=column)

    table = Table(title="ScamShield Bulk Scan Results")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Score", justify="center")
    table.add_column("Level", justify="center")
    table.add_column("Type", justify="center")
    table.add_column("Message (truncated)", max_width=60)

    for i, report in enumerate(reports, 1):
        color = _color_for_level(report.risk_score.level)
        msg_preview = report.message[:57] + "..." if len(report.message) > 60 else report.message
        table.add_row(
            str(i),
            f"[{color}]{report.risk_score.total}[/{color}]",
            f"[{color}]{report.risk_score.level}[/{color}]",
            report.scam_type,
            msg_preview,
        )

    console.print(table)
    console.print(f"\n[bold]{len(reports)}[/bold] messages scanned.\n")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
