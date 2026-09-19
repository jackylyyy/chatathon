# sentinel

**Snyk secures the code that exists. We secure the moment it gets written — and the moment someone has to understand it.**

Chatathon 09/19/2026.

---

## The gap we're going after

Snyk's four announced initiatives cluster around two things: agentic AI *writing* code (Evo, Malicious Code Defense) and testing or monitoring systems *after* they're built (Code Optimization Service, Runtime Insights). Two things aren't covered:

1. **The moment before code is written.** Snyk's remediation agent fixes vulnerabilities after they exist. Nothing stops an AI coding assistant from introducing one in the first place, because the assistant doesn't know better at the moment it's typing.
2. **Explainability for non-experts.** All four initiatives are built for security teams. Nothing helps an average developer understand *why* something is risky, in language they'd actually use.

`sentinel` is those two layers. It is not another scanner.

## What it does

```
                  ┌──────────────────────────────┐
  Snyk / SARIF ──▶│                              │──▶  prioritized briefing
  scan report     │   explainer core             │     (text / markdown / JSON)
                  │   Finding ──▶ Explanation    │
  agent's ───────▶│   (the only thing that       │──▶  allow / warn / block
  proposed edit   │    talks to the model)       │     + feedback for the agent
                  └──────────────────────────────┘
```

### 1. `sentinel explain` — "Why This Matters"

Takes scan output — usually a wall of CVE IDs and severity scores — and turns each finding into: what it means in *this* codebase, a realistic attack scenario, and a prioritized fix path.

The ranking is the part that matters. A scanner ranks by severity, which is a property of the vulnerability class. We re-rank by what the explanation revealed about *this instance*: how exploitable it actually is here, how much it would cost, and how cheap the fix is. That's what turns 40 findings into "fix these three today".

### 2. `sentinel guard` — "Agent Conscience"

Runs **automatically, before an AI agent's edit is applied**, as a Claude Code hook. If the change introduces something dangerous, the edit never happens and the agent gets a plain-English explanation injected into its context — so it **self-corrects instead of just getting blocked**.

A blocked edit with no explanation teaches an agent to try a variation. A blocked edit with a named safer pattern teaches it to write the right thing.

One command wires it in: `sentinel install-hook`. See [hooks/README.md](hooks/README.md).

---

## Presenting this

```bash
python scripts/present.py
```

The whole story in five acts, paced by the presenter — press Enter to advance, so you talk over a still screen instead of a scrolling one. It opens on the raw scan report (the problem), moves through `explain` and `guard`, and **Act 4 pipes a real tool call into the real hook** and shows the denial plus the exact text the agent gets back.

| Flag | |
|---|---|
| `--auto` | No pauses — for recording a screen capture. |
| `--act N` | Start at act N, for picking the demo up midway. |
| `--offline` | Never call the model. |

It writes nothing to disk, so it is safe to run live and safe to re-run. `tests/test_present.py` drives every act end to end, because a demo script that breaks on stage is the one failure that actually costs something.

For the landing page, serve the repo root and open <http://localhost:8080>:

```bash
python -m http.server 8080
```

---

## Quickstart

```bash
python -m venv .venv
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

On Windows:

```bash
.venv/Scripts/activate
```

```bash
pip install -e ".[dev]"
```

Then see both halves at once:

```bash
sentinel demo
```

### Explaining a scan report

```bash
sentinel explain examples/snyk-report.json
```

```bash
sentinel explain report.json --format md --out briefing.md
```

```bash
sentinel explain report.json --min-severity high --summary
```

### Checking a change by hand

```bash
sentinel guard --diff examples/agent-change.diff
```

```bash
git diff | sentinel guard --stdin
```

### Checking every AI edit automatically

```bash
sentinel install-hook
```

Run that once per checkout — it writes the interpreter path for *your* platform into `.claude/settings.json`, which a committed file cannot do for everyone at once. Then **restart Claude Code** so it picks up the hook, and ask it to write something unsafe: the edit gets refused and the agent is told why. Full details in [hooks/README.md](hooks/README.md).

### Seeing what the guardrail looks for

```bash
sentinel rules
```

## Credentials

Put an `ANTHROPIC_API_KEY` in `.env` (see `.env.example`). **Without a key everything still runs** — it falls back to the hand-written explanation attached to each rule. That's deliberate: the demo must never hard-fail in front of judges, and the offline output is the floor the model-generated output has to beat.

Model is `claude-opus-5`, set in [config.py](src/sentinel/config.py).

## Layout

| Path | What's there |
|---|---|
| [models.py](src/sentinel/models.py) | `Finding`, `Explanation`, `Verdict` — the shared vocabulary. **Read this first.** |
| [explain/explainer.py](src/sentinel/explain/explainer.py) | The core. Finding → Explanation, with offline fallback |
| [explain/prompts.py](src/sentinel/explain/prompts.py) | Where "explain it to a non-security developer" is enforced |
| [explain/prioritize.py](src/sentinel/explain/prioritize.py) | Re-ranking by real-world exploitability, not severity class |
| [guard/rules.py](src/sentinel/guard/rules.py) | 15 patterns, each with its own hand-written explanation |
| [guard/diff.py](src/sentinel/guard/diff.py) | Unified-diff parser — only added lines are judged |
| [guard/engine.py](src/sentinel/guard/engine.py) | Verdict + the feedback block injected into the agent |
| [hook.py](src/sentinel/hook.py) | The Claude Code PreToolUse integration |
| [ingest/](src/sentinel/ingest) | Snyk JSON and SARIF → `Finding`. Add a scanner in ~30 lines |
| [llm.py](src/sentinel/llm.py) | The only file that touches the Anthropic SDK |

Only added lines are ever judged — nobody is served by blocking an agent over a finding it didn't cause.

## Tests

```bash
pytest
```

104 tests, no network required. `pyright` is clean.

If VS Code shows red squiggles on `import typer` / `rich` / `anthropic`, it hasn't picked up the venv: run **Python: Select Interpreter** and choose `.venv`.

## Where this goes next

- **Dependency trust briefing.** `guard` already flags every new dependency as it enters a manifest (`dep.new-dependency`). The hook is there; what's missing is the briefing: maintainer activity, typosquat distance to popular names, install scripts. `examples/agent-change.diff` deliberately adds `node-fetchh`.
- **Agent provenance.** `Verdict` is already a record of what an agent proposed and why it was refused. Persisting those across a session gives an audit trail, and a reasoning-vs-diff mismatch check.
- **Reachability.** The biggest accuracy win for `explain`: check whether the vulnerable function is actually called before ranking it "fix now".

### Known rough edges

- The ruleset is regex over added lines. It sees one line at a time, so it can't tell a tainted variable from a constant. That's the right trade for something on the hot path of every edit, but it means false positives — the explanation layer is what makes them cheap to dismiss.
- The hook skips `tests/`, `examples/` and vendor directories, because a hardcoded password in a test fixture is not a leak. That also means it won't catch a real one there.
- Offline prioritization is flat on a dependency-only report: without a model it can't tell reachable from unreachable, so severity dominates. Run with a key to see the reordering.
