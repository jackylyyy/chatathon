"""Write the Claude Code hook registration into `.claude/settings.json`.

This exists because the hook command is not portable and cannot be. Claude
Code's `command` is a single string with no OS switch in it, and the console
script it has to invoke lives at `.venv/bin/sentinel` on macOS and Linux but
`.venv\\Scripts\\sentinel.exe` on Windows. A committed settings file can only
name one of them, so on the other platform the guardrail silently never fires -
the worst possible failure for a security tool, because nothing looks wrong.

So we generate it instead. `sentinel install-hook` writes the path for the
interpreter that is running it, which is by definition the right one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_DIR_VAR = "${CLAUDE_PROJECT_DIR}"
MATCHER = "Write|Edit|MultiEdit"
TIMEOUT_SECONDS = 30

# How we recognise a registration as ours when re-installing, so running the
# command twice updates one entry instead of stacking up duplicates.
OURS = "sentinel.hook"


def hook_command(project_root: Path, executable: str | None = None) -> str:
    """The command string Claude Code should run, for *this* platform.

    `-m sentinel.hook` rather than the `sentinel` console script: the module
    path is the same on every OS, so only the interpreter location varies.
    Relative to `${CLAUDE_PROJECT_DIR}` when the interpreter lives inside the
    project (the usual `.venv`), so the file stays shareable with teammates on
    the same platform; absolute otherwise, which at least works locally.
    """
    exe = Path(executable or sys.executable).resolve()
    try:
        rel = exe.relative_to(project_root.resolve()).as_posix()
        location = f"{PROJECT_DIR_VAR}/{rel}"
    except ValueError:
        location = exe.as_posix()
    return f'"{location}" -m {OURS} --fast'


def hook_entry(command: str) -> dict[str, Any]:
    return {
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": command, "timeout": TIMEOUT_SECONDS}],
    }


def _is_ours(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks") or []:
        if isinstance(hook, dict) and OURS in str(hook.get("command", "")):
            return True
    return False


def merge_settings(settings: dict[str, Any], command: str) -> dict[str, Any]:
    """Add (or update) our PreToolUse entry, leaving every other hook alone.

    Someone else's hooks in this file are not ours to drop, so we filter only
    the entries that invoke `sentinel.hook` and append a fresh one.
    """
    merged = dict(settings)
    hooks = dict(merged.get("hooks") or {})
    existing = hooks.get("PreToolUse")
    kept = [e for e in existing if not _is_ours(e)] if isinstance(existing, list) else []
    hooks["PreToolUse"] = [*kept, hook_entry(command)]
    merged["hooks"] = hooks
    return merged


def install(project_root: Path, executable: str | None = None) -> tuple[Path, str, bool]:
    """Write the registration. Returns (settings path, command, changed)."""
    settings_path = project_root / ".claude" / "settings.json"

    current: dict[str, Any] = {}
    if settings_path.is_file():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{settings_path} is not valid JSON ({exc})") from exc
        if not isinstance(loaded, dict):
            raise ValueError(f"{settings_path} should contain a JSON object")
        current = loaded

    command = hook_command(project_root, executable)
    updated = merge_settings(current, command)
    if updated == current:
        return settings_path, command, False

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
    return settings_path, command, True
