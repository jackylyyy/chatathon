"""A small unified-diff parser.

We only care about added lines and their line numbers in the new file: the
guardrail judges what the change introduces, not what was already there. Nobody
is served by blocking an agent over a pre-existing finding it did not cause.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class AddedLine:
    file: str
    line: int
    text: str


@dataclass(frozen=True)
class ParsedDiff:
    added: list[AddedLine]
    files: list[str]
    removed_count: int = 0

    @property
    def line_count(self) -> int:
        return len(self.added)


def parse_unified_diff(diff_text: str) -> ParsedDiff:
    added: list[AddedLine] = []
    files: list[str] = []
    removed = 0

    current_file: str | None = None
    new_lineno = 0
    in_hunk = False

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            current_file = _strip_prefix(raw[4:].strip())
            if current_file and current_file not in files:
                files.append(current_file)
            in_hunk = False
            continue

        if raw.startswith("--- ") or raw.startswith("diff --git"):
            in_hunk = False
            continue

        header = HUNK_HEADER.match(raw)
        if header:
            new_lineno = int(header.group(1))
            in_hunk = True
            continue

        if not in_hunk or current_file is None:
            continue

        if raw.startswith("+"):
            added.append(AddedLine(file=current_file, line=new_lineno, text=raw[1:]))
            new_lineno += 1
        elif raw.startswith("-"):
            removed += 1
        elif raw.startswith("\\"):
            # "\ No newline at end of file"
            continue
        else:
            # context line (leading space, or a bare empty line some tools emit)
            new_lineno += 1

    return ParsedDiff(added=added, files=files, removed_count=removed)


def _strip_prefix(path: str) -> str | None:
    """Turn `b/src/app.py\t2024-01-01` into `src/app.py`."""
    path = path.split("\t")[0].strip()
    if path in {"/dev/null", ""}:
        return None
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path


def synthesize_diff(file: str, content: str) -> str:
    """Wrap a whole file as an all-additions diff.

    Lets the guardrail run on a file an agent wants to create, where there is no
    real diff yet - the common case for a Write tool call.
    """
    lines = content.splitlines()
    body = "\n".join(f"+{line}" for line in lines)
    return (
        f"--- /dev/null\n"
        f"+++ b/{file}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{body}\n"
    )
