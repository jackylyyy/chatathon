"""Claude Code PreToolUse hook.

This is the piece that makes the guardrail real: instead of a human running
`conscience guard` on a diff, Claude Code calls this automatically every time
the agent tries to Write or Edit a file. If the change is dangerous the tool
call is denied and the explanation is handed back to the agent, which then
corrects itself.

The contract (from the Claude Code hooks docs):
  - stdin  : JSON with `tool_name`, `tool_input`, `cwd`
  - stdout : {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                     "permissionDecision": "deny",
                                     "permissionDecisionReason": "..."}}
  - exit 0 : proceed through the normal permission flow

Two rules govern everything here:

1. **Fail open.** A hook sits in front of every edit the agent makes. If this
   code raises, times out, or gets confused, it must let the edit through. A
   security tool that bricks the editor gets uninstalled within the hour.
2. **Judge only what the agent is adding.** We reconstruct the file as it will
   be and diff it against the file as it is, so line numbers are real and
   pre-existing code is never blamed on the agent.
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path
from typing import Any

from .config import Settings
from .guard.engine import Guard
from .models import Severity, Verdict

# Tool calls that can introduce code. Anything else is none of our business.
REVIEWABLE_TOOLS = {"Write", "Edit", "MultiEdit"}

# Paths where a "vulnerability" is usually a fixture, not a bug. Without this,
# editing our own test suite trips the hardcoded-credential rule on every
# example string - which is exactly the kind of false positive that teaches
# people to disable the tool.
EXCLUDED_DIRS = (
    "tests",
    "test",
    "examples",
    "fixtures",
    "__tests__",
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "site-packages",
)
EXCLUDED_NAME_HINTS = ("test_", "_test.", ".test.", ".spec.", "conftest.py")


class NotReviewable(Exception):
    """This tool call is not something we can or should judge."""


# -- working out what the change actually is --------------------------------


def should_skip(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    parts = normalized.split("/")
    if any(part in EXCLUDED_DIRS for part in parts):
        return True
    name = parts[-1] if parts else normalized
    return any(hint in name for hint in EXCLUDED_NAME_HINTS)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def proposed_content(tool_name: str, tool_input: dict[str, Any], cwd: Path) -> tuple[Path, str, str]:
    """Return (path, before, after) for a tool call, without touching disk.

    Raises NotReviewable when the call is not a code change we can model.
    """
    raw_path = tool_input.get("file_path") or tool_input.get("path")
    if not raw_path:
        raise NotReviewable("no file_path in tool_input")

    path = Path(raw_path)
    if not path.is_absolute():
        path = cwd / path

    if should_skip(str(path)):
        raise NotReviewable(f"excluded path: {path}")

    if tool_name == "Write":
        after = tool_input.get("content")
        if after is None:
            raise NotReviewable("Write with no content")
        return path, _read(path), after

    before = _read(path)

    if tool_name == "Edit":
        old = tool_input.get("old_string")
        new = tool_input.get("new_string")
        if old is None or new is None:
            raise NotReviewable("Edit without old_string/new_string")
        if not before:
            # Cannot locate the edit in a file we cannot read. Fall back to
            # treating the inserted text as new lines; line numbers will be
            # relative, but the finding is still correct.
            return path, "", new
        count = -1 if tool_input.get("replace_all") else 1
        return path, before, before.replace(old, new, count)

    if tool_name == "MultiEdit":
        edits = tool_input.get("edits") or []
        after = before
        for edit in edits:
            old, new = edit.get("old_string"), edit.get("new_string")
            if old is None or new is None:
                continue
            count = -1 if edit.get("replace_all") else 1
            after = after.replace(old, new, count)
        if after == before:
            raise NotReviewable("MultiEdit produced no change")
        return path, before, after

    raise NotReviewable(f"unhandled tool: {tool_name}")


def build_diff(path: Path, before: str, after: str, cwd: Path) -> str:
    """A real unified diff, so only genuinely new lines get judged."""
    if before == after:
        return ""

    try:
        label = path.relative_to(cwd).as_posix()
    except ValueError:
        label = path.as_posix()

    lines = difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f"a/{label}",
        tofile=f"b/{label}",
        lineterm="",
        n=0,
    )
    return "\n".join(lines)


# -- the hook response ------------------------------------------------------


def deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def review(payload: dict[str, Any], *, fast: bool = False, block_at: Severity = Severity.HIGH) -> tuple[dict[str, Any] | None, str]:
    """Judge one tool call.

    Returns (response_to_print_or_None, human_readable_log_line).
    """
    tool_name = payload.get("tool_name", "")
    if tool_name not in REVIEWABLE_TOOLS:
        return None, f"skipped: {tool_name} is not a code-writing tool"

    tool_input = payload.get("tool_input") or {}
    cwd = Path(payload.get("cwd") or ".")

    try:
        path, before, after = proposed_content(tool_name, tool_input, cwd)
    except NotReviewable as exc:
        return None, f"skipped: {exc}"

    diff_text = build_diff(path, before, after, cwd)
    if not diff_text.strip():
        return None, "skipped: no net change"

    settings = Settings.from_env()
    verdict: Verdict = Guard(settings, block_at=block_at, explain=not fast).review_diff(
        diff_text, cwd
    )

    if verdict.decision == "block":
        worst = verdict.findings[0].finding if verdict.findings else None
        label = worst.title if worst else "policy violation"
        return deny(verdict.agent_feedback), f"DENIED: {label} in {path.name}"

    if verdict.findings:
        names = ", ".join(sorted({f.finding.title for f in verdict.findings}))
        return None, f"allowed with notes: {names}"

    return None, "allowed: nothing flagged"


def main(argv: list[str] | None = None) -> int:
    """Entry point. Never raises, never blocks on an internal error."""
    argv = argv if argv is not None else sys.argv[1:]
    fast = "--fast" in argv

    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, OSError) as exc:
        print(f"conscience hook: could not read input ({exc})", file=sys.stderr)
        return 0

    try:
        response, log_line = review(payload, fast=fast)
    except Exception as exc:  # fail open, loudly
        print(f"conscience hook: internal error, allowing ({exc!r})", file=sys.stderr)
        return 0

    print(f"conscience hook: {log_line}", file=sys.stderr)
    if response is not None:
        print(json.dumps(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
