# conscience

**Snyk secures the code that exists. We secure the moment it gets written — and the moment someone has to understand it.**

Chatathon, 09/19/2026.

---

## The gap we're going after

Snyk's four announced initiatives cluster around two things: agentic AI *writing* code (Evo, Malicious Code Defense) and testing or monitoring systems *after* they're built (Code Optimization Service, Runtime Insights). Two things aren't covered:

1. **The moment before code is written.** Snyk's remediation agent fixes vulnerabilities after they exist. Nothing stops an AI coding assistant from introducing one in the first place, because the assistant doesn't know better at the moment it's typing.
2. **Explainability for non-experts.** All four initiatives are built for security teams. Nothing helps an average developer understand *why* something is risky, in language they'd actually use.

`conscience` is those two layers. It is not another scanner.

## Two front ends, one core

```
                  ┌──────────────────────────────┐
  Snyk / SARIF ──▶│                              │──▶  prioritized briefing
  scan report     │   explainer core             │     (text / markdown / JSON)
                  │   Finding ──▶ Explanation    │
  agent's ───────▶│   (the only thing that       │──▶  allow / warn / block
  proposed diff   │    talks to the model)       │     + feedback for the agent
                  └──────────────────────────────┘
```

### `conscience explain` — "Why This Matters" (pitch #2)

Takes scan output — usually a wall of CVE IDs and severity scores — and turns each finding into: what it means in *this* codebase, a realistic attack scenario, and a prioritized fix path.

The ranking is the part that matters. A scanner ranks by severity, which is a property of the vulnerability class. We re-rank by what the explanation revealed about *this instance*: how exploitable it actually is here, how much it would cost, and how cheap the fix is. That's what turns 40 findings into "fix these three today".

### `conscience guard` — "Agent Conscience" (pitch #1)

Sits between an AI coding agent and the codebase. Before a suggested diff gets applied, it's checked against the ruleset, and — the important part — the agent gets a natural-language explanation injected back into its context so it **self-corrects instead of just getting blocked**.

Exit code is `1` on block and `0` otherwise, so it drops straight into a pre-commit hook or an agent tool-use gate.

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/activate
pip install -e ".[dev]"
```

Run both halves against the bundled examples:

```bash
conscience demo
```

Explain a scan report:

```bash
conscience explain examples/snyk-report.json
```

```bash
conscience explain report.json --format md --out briefing.md
```

```bash
conscience explain report.json --min-severity high --summary
```

Judge a change before it lands:

```bash
conscience guard --diff examples/agent-change.diff
```

```bash
git diff | conscience guard --stdin
```

```bash
conscience guard --file src/api/new_endpoint.py
```

```bash
conscience guard --stdin --fast
```

See what the guardrail looks for:

```bash
conscience rules
```

### Credentials

Put an `ANTHROPIC_API_KEY` in `.env` (see `.env.example`). **Without a key everything still runs** — it falls back to the hand-written explanation attached to each rule. That's deliberate: the demo must never hard-fail in front of judges, and the offline output is the floor the model-generated output has to beat.

Model is `claude-opus-5`, set in [config.py](src/conscience/config.py).

## Layout

| Path | What's there |
|---|---|
| [models.py](src/conscience/models.py) | `Finding`, `Explanation`, `Verdict` — the shared vocabulary |
| [explain/explainer.py](src/conscience/explain/explainer.py) | The core. Finding → Explanation, with offline fallback |
| [explain/prompts.py](src/conscience/explain/prompts.py) | Where the "explain it to a non-security developer" rules live |
| [explain/prioritize.py](src/conscience/explain/prioritize.py) | Re-ranking by real-world exploitability, not severity class |
| [guard/rules.py](src/conscience/guard/rules.py) | 15 patterns, each with its own hand-written explanation |
| [guard/diff.py](src/conscience/guard/diff.py) | Unified-diff parser — only added lines are judged |
| [guard/engine.py](src/conscience/guard/engine.py) | Verdict + the feedback block injected into the agent |
| [ingest/](src/conscience/ingest) | Snyk JSON and SARIF → `Finding`. Add a scanner in ~30 lines |
| [llm.py](src/conscience/llm.py) | The only file that touches the Anthropic SDK |

Only added lines are judged, never surrounding context — nobody is served by blocking an agent over a finding it didn't cause.

## Tests

```bash
pytest
```

44 tests, no network required. `pyright` is clean.

If VS Code shows red squiggles on `import typer` / `rich` / `anthropic`, it hasn't picked up the venv: run **Python: Select Interpreter** and choose `.venv`. [.vscode/settings.json](.vscode/settings.json) points at it by default.

## Where this goes next

Scoped for the chatathon, in rough order of payoff:

- **Wire `guard` into a real Claude Code `PreToolUse` hook.** The CLI already speaks JSON on stdout and signals through its exit code; what's missing is the hook shim that reads the tool-call payload and feeds `agent_feedback` back. This is the demo that lands.
- **Dependency trust briefing (pitch #4).** `guard` already flags every new dependency as it enters a manifest — `dep.new-dependency`. The hook is there; what's missing is the briefing: maintainer activity, typosquat distance to popular names, install scripts. `examples/agent-change.diff` deliberately adds `node-fetchh`.
- **Agent provenance (pitch #3).** `Verdict` is already a record of what an agent proposed and why it was refused. Persisting those across a session gives the audit trail, and the reasoning-vs-diff mismatch check.
- **Reachability.** The single biggest accuracy win for `explain`: check whether the vulnerable function is actually called before ranking it "fix now".
- **Prompt caching** on the explainer system prompt — it's stable across every finding, so it should be a cached prefix.

### Known rough edges

- The ruleset is regex over added lines. It sees one line at a time, so it can't tell a tainted variable from a constant. That's the right trade for something running on every edit, but it means false positives — the explanation layer is what makes them cheap to dismiss.
- Offline prioritization is flat on a dependency-only report: without a model it can't tell reachable from unreachable, so severity dominates. Run with a key to see the reordering.
