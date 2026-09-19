"""Terminal rendering.

The whole pitch is legibility, so the output is part of the product, not a
debug view. Keep it calm: colour carries severity and nothing else.
"""

from __future__ import annotations

import json

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule as HRule
from rich.table import Table
from rich.text import Text

from .explain.prioritize import triage_bucket
from .models import ExplainedFinding, Severity, Verdict

console = Console()

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

DECISION_STYLE = {"block": "bold white on red", "warn": "bold yellow", "allow": "bold green"}


def severity_tag(severity: Severity) -> Text:
    return Text(f" {severity.value.upper()} ", style=SEVERITY_STYLE[severity])


def summary_table(items: list[ExplainedFinding]) -> Table:
    table = Table(show_lines=False, header_style="bold", expand=True)
    table.add_column("#", width=3, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Score", width=6, justify="right")
    table.add_column("Do", width=16)
    table.add_column("What")
    table.add_column("Where", overflow="fold")

    for item in items:
        table.add_row(
            str(item.rank),
            severity_tag(item.finding.severity),
            f"{item.priority:.0f}",
            triage_bucket(item),
            item.explanation.headline,
            item.finding.location,
        )
    return table


def finding_panel(item: ExplainedFinding) -> Panel:
    f, e = item.finding, item.explanation
    body: list = []

    body.append(Text(e.what_it_means))
    body.append(Text(""))
    body.append(Text("If someone attacks this", style="bold"))
    body.append(Text(e.attack_scenario))
    body.append(Text(""))
    body.append(Text("Why it matters here", style="bold"))
    body.append(Text(e.why_here))
    body.append(Text(""))
    body.append(Text(f"The fix ({e.fix_effort})", style="bold"))
    body.append(Text(e.fix_summary))
    for step_no, step in enumerate(e.fix_steps, start=1):
        body.append(Text(f"  {step_no}. {step}"))

    if e.safer_pattern:
        body.append(Text(""))
        body.append(Text("Safer pattern", style="bold"))
        body.append(Text(e.safer_pattern, style="green"))

    if f.snippet:
        body.append(Text(""))
        body.append(Text("Your code", style="bold"))
        body.append(Text(f.snippet, style="red"))

    body.append(Text(""))
    meta = f"exploitability {e.exploit_likelihood}/5 - blast radius {e.blast_radius}/5"
    if f.cve:
        meta += f" - {', '.join(f.cve)}"
    meta += f" - explained by {e.generated_by}"
    body.append(Text(meta, style="dim"))

    title = Text()
    title.append_text(severity_tag(f.severity))
    title.append(f"  #{item.rank}  {e.headline}")

    return Panel(
        Group(*body),
        title=title,
        subtitle=Text(f.location, style="dim"),
        subtitle_align="left",
        border_style=SEVERITY_STYLE[f.severity].replace("bold white on ", ""),
        padding=(1, 2),
    )


def render_report(items: list[ExplainedFinding], *, detail: bool = True, source: str = "") -> None:
    if not items:
        console.print("[green]No findings. Nothing to explain.[/green]")
        return

    header = f"{len(items)} finding(s)"
    if source:
        header += f" from {source}"
    console.print()
    console.print(HRule(header))
    console.print(summary_table(items))

    if detail:
        console.print()
        for item in items:
            console.print(finding_panel(item))
            console.print()


def render_verdict(verdict: Verdict, *, show_feedback: bool = True) -> None:
    style = DECISION_STYLE[verdict.decision]
    label = {
        "block": "BLOCKED - this change was not applied",
        "warn": "ALLOWED WITH WARNINGS",
        "allow": "ALLOWED - nothing flagged",
    }[verdict.decision]

    console.print()
    console.print(Text(f" {label} ", style=style))
    console.print(
        Text(
            f"{verdict.lines_reviewed} added line(s) across "
            f"{len(verdict.files_reviewed)} file(s)",
            style="dim",
        )
    )

    if verdict.findings:
        console.print(summary_table(verdict.findings))
        console.print()
        for item in verdict.findings:
            console.print(finding_panel(item))
            console.print()

    if show_feedback and verdict.agent_feedback:
        console.print(
            Panel(
                verdict.agent_feedback,
                title="Injected back into the agent's context",
                border_style="blue",
                padding=(1, 2),
            )
        )


def to_json(items: list[ExplainedFinding]) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], indent=2)


def verdict_to_json(verdict: Verdict) -> str:
    return json.dumps(verdict.model_dump(mode="json"), indent=2)


def to_markdown(items: list[ExplainedFinding], title: str = "Security briefing") -> str:
    lines = [f"# {title}", "", f"{len(items)} finding(s), highest priority first.", ""]
    for item in items:
        f, e = item.finding, item.explanation
        lines += [
            f"## {item.rank}. {e.headline}",
            "",
            f"- **Severity:** {f.severity.value} | **Priority:** {item.priority:.0f}/100 "
            f"| **Action:** {triage_bucket(item)}",
            f"- **Where:** `{f.location}`",
            "",
            f"**What it means.** {e.what_it_means}",
            "",
            f"**If someone attacks this.** {e.attack_scenario}",
            "",
            f"**Why it matters here.** {e.why_here}",
            "",
            f"**Fix ({e.fix_effort}).** {e.fix_summary}",
            "",
        ]
        lines += [f"{n}. {s}" for n, s in enumerate(e.fix_steps, start=1)]
        if e.safer_pattern:
            lines += ["", "```", e.safer_pattern, "```"]
        lines.append("")
    return "\n".join(lines)
