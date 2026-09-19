"""Stage-managed demo: the whole Sentinel story, in five acts, for an audience.

`sentinel demo` runs both halves back to back, which is the right thing when
you want to check the tool still works. It is the wrong thing in front of a
room: it scrolls past at machine speed, it opens on the answer instead of the
problem, and it never shows the part that actually distinguishes this project
- the hook firing inside Claude Code.

This script is the presenting version. It pauses between acts so you talk over
a still screen instead of a scrolling one, it opens on the raw scan report so
the audience feels the problem before seeing the fix, and Act 4 shells out to
the real hook the same way Claude Code does.

    python scripts/present.py              # presenter-paced, press Enter to advance
    python scripts/present.py --auto       # unattended, for a recording
    python scripts/present.py --act 4      # jump straight to one act
    python scripts/present.py --offline    # never call the model

Nothing here writes to disk, so it is safe to run live and safe to re-run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"
sys.path.insert(0, str(REPO_ROOT / "src"))

from rich.panel import Panel  # noqa: E402
from rich.syntax import Syntax  # noqa: E402
from rich.text import Text  # noqa: E402

from sentinel import __version__, render  # noqa: E402
from sentinel.config import Settings, has_credentials  # noqa: E402
from sentinel.explain.explainer import Explainer  # noqa: E402
from sentinel.guard.engine import Guard  # noqa: E402
from sentinel.guard.rules import RULES  # noqa: E402
from sentinel.ingest import load_findings  # noqa: E402

console = render.console

SITE_URL = "http://localhost:8080"

SCAN_REPORT = EXAMPLES / "snyk-report.json"
AGENT_DIFF = EXAMPLES / "agent-change.diff"
# The tool call Act 4 replays: an agent asked for a login endpoint, writing
# exactly the kind of code an LLM produces when nobody is watching. It lives in
# examples/ rather than inline here because the guardrail is running on this
# repo, and it would (correctly) refuse to let anyone save those lines into
# scripts/.
AGENT_WRITE = EXAMPLES / "agent-write.json"


# -- staging ----------------------------------------------------------------


class Stage:
    """Act numbering and the pause between them."""

    def __init__(self, auto: bool, pause_seconds: float = 2.5) -> None:
        self.auto = auto
        self.pause_seconds = pause_seconds

    def act(self, number: int, title: str, subtitle: str) -> None:
        console.print()
        console.rule(f"[bold]ACT {number}[/bold]  [bold white]{title}[/bold white]")
        console.print(f"[dim]{subtitle}[/dim]")
        console.print()

    def beat(self, message: str) -> None:
        """A line of narration between two pieces of output."""
        console.print(f"\n[bold cyan]>[/bold cyan] {message}\n")

    def pause(self, prompt: str) -> None:
        if self.auto:
            if self.pause_seconds > 0:
                time.sleep(self.pause_seconds)
            return
        console.print()
        try:
            input(f"    -- Enter for {prompt} --")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]ended early[/dim]")
            raise SystemExit(0)


# -- acts -------------------------------------------------------------------


def act1_the_problem(stage: Stage, settings: Settings) -> None:
    stage.act(
        1,
        "What a developer actually receives",
        "The scanner has already done its job. This is the output.",
    )

    report = json.loads(SCAN_REPORT.read_text(encoding="utf-8"))
    rows = []
    for vuln in report.get("vulnerabilities", []):
        cves = vuln.get("identifiers", {}).get("CVE", [])
        ident = ", ".join(cves) or vuln.get("id", "")
        package = f'{vuln.get("packageName", "")}@{vuln.get("version", "")}'
        rows.append(f'{vuln.get("severity", "?"):>8}  {ident:<18}  {package}')

    console.print(
        Panel(
            "\n".join(rows),
            title="[dim]snyk test --json[/dim]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print(
        "[dim]Severity is a property of the vulnerability class, not of this "
        "codebase. Nothing here says which one matters on Monday morning.[/dim]"
    )


def act2_explain(stage: Stage, settings: Settings) -> None:
    stage.act(
        2,
        "sentinel explain - why this matters",
        "Same findings, re-ranked by what they mean here.",
    )

    findings, detected = load_findings(SCAN_REPORT)
    with render.status(f"Explaining {len(findings)} finding(s)..."):
        items = Explainer(settings).explain_all(findings)

    render.render_report(items, detail=False, source=detected)
    if items:
        stage.beat("And each one opens into something a non-specialist can act on:")
        console.print(render.finding_panel(items[0]))


def act3_guard(stage: Stage, settings: Settings) -> None:
    stage.act(
        3,
        "sentinel guard - judging a change before it lands",
        "An AI agent has proposed a diff. It has not been applied yet.",
    )

    diff_text = AGENT_DIFF.read_text(encoding="utf-8")
    console.print(
        Panel(
            Syntax(diff_text, "diff", theme="ansi_dark", word_wrap=True),
            title="[dim]the agent's proposed change[/dim]",
            border_style="yellow",
            padding=(0, 1),
        )
    )

    stage.pause("the verdict")

    with render.status("Reviewing the proposed change..."):
        verdict = Guard(settings).review_diff(diff_text)
    render.render_verdict(verdict)


def act4_hook(stage: Stage, settings: Settings) -> None:
    stage.act(
        4,
        "The hook - this is the part that is not a linter",
        "Claude Code hands every Write and Edit to Sentinel before it touches disk.",
    )

    payload = json.loads(AGENT_WRITE.read_text(encoding="utf-8"))
    payload.pop("_comment", None)
    # The hook resolves a relative file_path against cwd, so it has to be the
    # repo it is guarding - which is where Claude Code would have run it.
    payload["cwd"] = str(REPO_ROOT)
    target = payload["tool_input"]["file_path"]

    console.print(
        Panel(
            Syntax(
                payload["tool_input"]["content"],
                "python",
                theme="ansi_dark",
                line_numbers=True,
            ),
            title=f"[dim]agent wants to Write {target}[/dim]",
            border_style="yellow",
            padding=(0, 1),
        )
    )

    stage.beat(
        "Claude Code pipes that tool call, as JSON, into the registered hook "
        "command - literally this:"
    )
    console.print(
        f'    [dim]"{Path(sys.executable).as_posix()}" -m sentinel.hook --fast[/dim]'
    )

    stage.pause("the hook's decision")

    result = subprocess.run(
        [sys.executable, "-m", "sentinel.hook", "--fast"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    if result.stderr.strip():
        console.print(f"[dim]stderr: {result.stderr.strip()}[/dim]\n")

    if not result.stdout.strip():
        console.print(
            "[yellow]The hook allowed this write - nothing was flagged.[/yellow]"
        )
        return

    specific = json.loads(result.stdout)["hookSpecificOutput"]

    console.print(
        Panel(
            Text(
                specific["permissionDecision"].upper(),
                style="bold white on red",
                justify="center",
            ),
            border_style="red",
            padding=(0, 2),
            title="[dim]permissionDecision[/dim]",
        )
    )
    console.print(
        f"[bold]{target} was never written.[/bold] And this is the text that "
        "goes into the agent's context:\n"
    )
    console.print(
        Panel(
            specific["permissionDecisionReason"],
            border_style="magenta",
            padding=(1, 2),
        )
    )
    console.print(
        "[dim]A blocked edit with no explanation teaches an agent to try a "
        "variation. A blocked edit with a named safer pattern teaches it to "
        "write the right thing.[/dim]"
    )


def act5_site(stage: Stage, settings: Settings) -> None:
    stage.act(
        5,
        "The landing page",
        "Generated from the same ruleset the guardrail runs on.",
    )
    console.print(
        Panel(
            f"[bold cyan]{SITE_URL}[/bold cyan]\n\n"
            "[dim]Serve it from the repo root with:[/dim]\n"
            "    python -m http.server 8080\n\n"
            f"[dim]All {len(RULES)} rules on that page are read out of "
            "guard/rules.py by scripts/sync_site.py. The page cannot drift from "
            "the code, because a test fails if it does.[/dim]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


# -- driver -----------------------------------------------------------------

ACTS = (
    ("What a developer receives", act1_the_problem),
    ("sentinel explain", act2_explain),
    ("sentinel guard", act3_guard),
    ("the hook", act4_hook),
    ("the landing page", act5_site),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auto", action="store_true", help="No pauses; for recording.")
    parser.add_argument(
        "--pause",
        type=float,
        default=2.5,
        metavar="SECONDS",
        help="Beat between acts under --auto. 0 for as fast as it will go.",
    )
    parser.add_argument("--offline", action="store_true", help="Never call the model.")
    parser.add_argument(
        "--act", type=int, default=0, metavar="N", help=f"Start at act N (1-{len(ACTS)})."
    )
    args = parser.parse_args(argv)

    missing = [p.name for p in (SCAN_REPORT, AGENT_DIFF, AGENT_WRITE) if not p.is_file()]
    if missing:
        console.print(f"[red]Missing example file(s): {', '.join(missing)}[/red]")
        return 2

    stage = Stage(auto=args.auto, pause_seconds=args.pause)
    settings = Settings.from_env(offline=args.offline or None)

    console.print()
    console.print(
        Panel(
            f"[bold white]SENTINEL[/bold white]  [dim]v{__version__}[/dim]\n\n"
            "Your agent writes it. Sentinel reads it first.\n\n"
            "[dim]Snyk secures the code that exists. We secure the moment it "
            "gets written - and the moment someone has to understand it.[/dim]",
            border_style="magenta",
            padding=(1, 4),
        )
    )

    if settings.offline:
        console.print("[dim]Offline: explanations come from the built-in ruleset.[/dim]")
    elif not has_credentials():
        console.print(
            "[yellow]No ANTHROPIC_API_KEY - running on built-in explanations. "
            "The demo works either way.[/yellow]"
        )
    else:
        console.print(f"[green]Model: {settings.model}[/green]")

    start = min(max(args.act, 1), len(ACTS)) if args.act else 1

    for number, (label, act) in enumerate(ACTS[start - 1 :], start=start):
        stage.pause(f"Act {number} - {label}")
        act(stage, settings)

    console.print()
    console.rule("[bold magenta]sentinel install-hook - and it is live[/bold magenta]")
    console.print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
