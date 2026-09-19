"""Command line entry point.

    conscience explain report.json      # pitch #2 - make a scan readable
    conscience guard --diff change.diff # pitch #1 - judge a change before it lands
    conscience rules                    # what the guardrail looks for
    conscience demo                     # both, on the bundled examples
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from . import __version__, render
from .config import Settings, has_credentials
from .explain.explainer import Explainer
from .guard.engine import Guard
from .guard.rules import RULES
from .ingest import UnknownReportFormat, load_findings
from .models import Severity

app = typer.Typer(
    add_completion=False,
    help="Understand security findings, and stop AI agents from writing new ones.",
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def _settings(offline: bool) -> Settings:
    settings = Settings.from_env(offline=offline or None)
    if settings.offline:
        render.notice(
            "[dim]Running offline: explanations come from the built-in ruleset.[/dim]"
        )
    elif not has_credentials():
        render.notice(
            "[yellow]No ANTHROPIC_API_KEY found - falling back to built-in "
            "explanations. Set the key for the good ones.[/yellow]"
        )
    return settings


@app.command()
def explain(
    report: Path = typer.Argument(..., help="Snyk JSON or SARIF scan report."),
    limit: int = typer.Option(0, "--limit", "-n", help="Only explain the top N findings."),
    min_severity: str = typer.Option(
        "low", "--min-severity", help="critical | high | medium | low | info"
    ),
    output_format: str = typer.Option("text", "--format", "-f", help="text | json | md"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write to a file."),
    summary_only: bool = typer.Option(False, "--summary", help="Table only, no detail."),
    repo: Optional[Path] = typer.Option(
        None, "--repo", help="Repo root, so findings can be read in context."
    ),
    offline: bool = typer.Option(False, "--offline", help="Never call the model."),
) -> None:
    """Turn a wall of CVE IDs into something a developer will actually act on."""
    try:
        findings, detected = load_findings(report)
    except FileNotFoundError:
        render.error(f"No such report: {report}")
        raise typer.Exit(code=2)
    except UnknownReportFormat as exc:
        render.error(str(exc))
        raise typer.Exit(code=2)

    floor = Severity.parse(min_severity).rank
    findings = [f for f in findings if f.severity.rank >= floor]
    findings.sort(key=lambda f: -f.severity.rank)
    if limit > 0:
        findings = findings[:limit]

    if findings:
        settings = _settings(offline)
        with render.status(f"Explaining {len(findings)} finding(s)..."):
            items = Explainer(settings).explain_all(findings, repo)
    else:
        # Still emit a valid empty document, so a consumer parsing our stdout
        # does not have to special-case "clean".
        render.notice("[green]Nothing at or above that severity. Good.[/green]")
        items = []

    title = f"Security briefing ({detected})"
    if output_format == "json":
        payload = render.to_json(items)
    elif output_format in {"md", "markdown"}:
        payload = render.to_markdown(items, title=title)
    else:
        payload = None

    if payload is not None:
        if out:
            out.write_text(payload, encoding="utf-8")
            render.notice(f"[green]Wrote {out}[/green]")
        else:
            print(payload)
        return

    if items:
        render.render_report(items, detail=not summary_only, source=detected)
    if out:
        out.write_text(render.to_markdown(items, title=title), encoding="utf-8")
        render.notice(f"[green]Also wrote {out}[/green]")


@app.command()
def guard(
    diff: Optional[Path] = typer.Option(None, "--diff", "-d", help="Unified diff file."),
    file: Optional[Path] = typer.Option(
        None, "--file", help="Treat a whole file as a proposed addition."
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read the diff from stdin."),
    output_format: str = typer.Option("text", "--format", "-f", help="text | json"),
    block_at: str = typer.Option("high", "--block-at", help="Severity that blocks."),
    fast: bool = typer.Option(
        False, "--fast", help="Rules only, no model call. Use in a hot edit loop."
    ),
    repo: Optional[Path] = typer.Option(None, "--repo", help="Repo root for context."),
    offline: bool = typer.Option(False, "--offline", help="Never call the model."),
) -> None:
    """Review a change an agent wants to make, before it is applied.

    Exit code is 0 for allow/warn and 1 for block, so it drops straight into a
    pre-commit hook or an agent tool-use gate.
    """
    if stdin:
        diff_text = sys.stdin.read()
        source = "stdin"
    elif diff:
        diff_text = diff.read_text(encoding="utf-8")
        source = str(diff)
    elif file:
        content = file.read_text(encoding="utf-8")
        settings = _settings(offline)
        verdict = Guard(
            settings, block_at=Severity.parse(block_at), explain=not fast
        ).review_file(str(file), content, repo)
        _emit_verdict(verdict, output_format)
        raise typer.Exit(code=0 if verdict.ok else 1)
    else:
        render.error("Give me one of --diff, --file or --stdin.")
        raise typer.Exit(code=2)

    if not diff_text.strip():
        render.notice(f"[yellow]Empty diff from {source}, nothing to review.[/yellow]")
        return

    settings = _settings(offline)
    guardrail = Guard(settings, block_at=Severity.parse(block_at), explain=not fast)

    with render.status("Reviewing the proposed change..."):
        verdict = guardrail.review_diff(diff_text, repo)

    _emit_verdict(verdict, output_format)
    raise typer.Exit(code=0 if verdict.ok else 1)


def _emit_verdict(verdict, output_format: str) -> None:
    if output_format == "json":
        print(render.verdict_to_json(verdict))
    else:
        render.render_verdict(verdict)


@app.command()
def hook(
    fast: bool = typer.Option(
        False, "--fast", help="Rules only, no model call. Faster, less helpful feedback."
    ),
) -> None:
    """Run as a Claude Code PreToolUse hook. Reads the tool call as JSON on stdin.

    You do not run this by hand - Claude Code runs it for you once it is
    registered in .claude/settings.json. See hooks/README.md.
    """
    from .hook import main as hook_main

    raise typer.Exit(code=hook_main(["--fast"] if fast else []))


@app.command()
def rules() -> None:
    """List what the guardrail checks for."""
    table = Table(header_style="bold", expand=True)
    table.add_column("Rule", overflow="fold")
    table.add_column("Severity", width=10)
    table.add_column("Applies to", width=14)
    table.add_column("Catches", overflow="fold")

    for rule in sorted(RULES, key=lambda r: (-r.severity.rank, r.id)):
        scope = ", ".join(e.lstrip(".") for e in rule.extensions) if rule.extensions else "any file"
        table.add_row(
            rule.id,
            render.severity_tag(rule.severity),
            scope,
            rule.name,
        )
    render.console.print(table)
    render.console.print(f"[dim]{len(RULES)} rules.[/dim]")


@app.command()
def demo(
    offline: bool = typer.Option(False, "--offline", help="Never call the model."),
) -> None:
    """Run both halves against the bundled examples."""
    scan = EXAMPLES / "snyk-report.json"
    diff = EXAMPLES / "agent-change.diff"

    if not scan.exists() or not diff.exists():
        render.error(f"Examples not found under {EXAMPLES}")
        raise typer.Exit(code=2)

    render.console.rule("[bold]1. Why This Matters - explaining a scan[/bold]")
    findings, detected = load_findings(scan)
    settings = _settings(offline)
    with render.status("Explaining..."):
        items = Explainer(settings).explain_all(findings)
    render.render_report(items, source=detected)

    render.console.rule("[bold]2. Agent Conscience - judging a proposed change[/bold]")
    with render.status("Reviewing..."):
        verdict = Guard(settings).review_diff(diff.read_text(encoding="utf-8"))
    render.render_verdict(verdict)


@app.command()
def version() -> None:
    """Print the version."""
    render.console.print(f"conscience {__version__}")


if __name__ == "__main__":
    app()
