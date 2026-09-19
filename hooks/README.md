# Running conscience as a Claude Code hook

This is the piece that makes the guardrail real. Instead of a human
remembering to run `conscience guard`, Claude Code runs it automatically
before every `Write` and `Edit`, and hands the explanation back to the agent
when a change is refused.

## It is already wired up

[`.claude/settings.json`](../.claude/settings.json) registers the hook for this
project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "\"${CLAUDE_PROJECT_DIR}/.venv/Scripts/conscience.exe\" hook --fast",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

**Restart Claude Code after adding this.** Hook configuration is captured at
startup, so a newly-added hook does not fire in an already-running session.

### On macOS or Linux

Swap the path - the venv puts executables in `bin`, not `Scripts`:

```json
"command": "\"${CLAUDE_PROJECT_DIR}/.venv/bin/conscience\" hook --fast"
```

## What happens

```
agent tries to Write a file
          │
          ▼
  Claude Code pauses, sends the tool call to `conscience hook` as JSON
          │
          ▼
  we reconstruct the file as it WILL be, diff it against what it IS,
  and run the ruleset over only the added lines
          │
          ├── nothing found ──▶ exit 0, the write proceeds. Agent sees nothing.
          │
          └── something HIGH+ ──▶ permissionDecision: "deny"
                                  the write never happens, and the
                                  explanation goes into the agent's context
```

The agent then reads *why* it was refused, and rewrites the code. That is the
whole idea: a blocked edit with no explanation just teaches an agent to try a
variation, but a blocked edit with a named safer pattern teaches it to write
the right thing.

## Testing it without an agent

The hook reads the same JSON Claude Code would send, so you can drive it by
hand:

```bash
echo '{"tool_name":"Write","cwd":".","tool_input":{"file_path":"api.py","content":"import os\nos.system(\"rm \" + user_input)\n"}}' | conscience hook --fast
```

You should see a `permissionDecision: "deny"` with the explanation. Swap in
harmless content and you get a single line on stderr and nothing on stdout.

## Design choices worth knowing

**It fails open.** Every branch that could raise returns exit 0 instead. A hook
sits in front of every edit; one that bricks the editor when it hits a bug gets
uninstalled within the hour. Any internal error is logged to stderr and the
edit proceeds.

**It only judges added lines.** We reconstruct the file as it will be and diff
it against the file as it is. Pre-existing problems are never blamed on the
agent - otherwise the first edit to any legacy file would be refused, and you
would turn the hook off.

**It skips test and example directories.** A hardcoded password in
`tests/test_auth.py` is a fixture, not a leak. Without this exclusion the hook
fires constantly on its own test suite, which is exactly the false-positive
pattern that trains people to ignore security tools. The list is
`EXCLUDED_DIRS` in [hook.py](../src/conscience/hook.py).

**`--fast` by default.** The hook runs on every edit, so it uses the built-in
rule explanations rather than calling the model. Drop `--fast` to have Claude
write a bespoke explanation of each finding - better feedback, a few seconds
slower, and only when something is actually found.

## Turning it off

Delete the `hooks` block from `.claude/settings.json`, or set the severity that
blocks higher than anything the rules produce. `conscience rules` lists every
rule and its severity.
