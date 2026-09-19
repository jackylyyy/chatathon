"""The demo script has to survive being run in front of people.

`scripts/present.py` is the thing that gets driven live, which makes it the
worst place in the repo for a regression: a rename in `render.py` or a renamed
example file would not break a single other test, and would be discovered on
stage. These tests run the real script end to end.

They run it offline so nothing here touches the network, and `--auto` so
nothing waits on a keypress.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "present.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import present  # noqa: E402


def run_present(*args: str) -> subprocess.CompletedProcess[str]:
    """Drive the script the way a presenter would, minus the pauses.

    `encoding="utf-8"` is not optional: the script draws rich's box characters,
    and `text=True` alone decodes the pipe with the locale codec - cp1252 on
    Windows - which raises in the reader thread and hands back a `None` stdout.
    """
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--auto", "--pause", "0", "--offline", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        timeout=180,
    )


def test_the_whole_show_runs_to_the_end():
    result = run_present()
    assert result.returncode == 0, result.stderr
    # The closing rule only prints if every act got there.
    assert "install-hook" in result.stdout


@pytest.mark.parametrize("act", [1, 2, 3, 4, 5])
def test_each_act_can_be_started_from_cold(act: int):
    """`--act N` is what you reach for when a demo has to be picked up midway."""
    result = run_present("--act", str(act))
    assert result.returncode == 0, result.stderr
    assert f"ACT {act}" in result.stdout


def test_act_four_actually_denies_the_write():
    """The demo's central claim: the hook refuses the edit and says why.

    If the ruleset ever stops catching this payload, the live demo silently
    becomes a slide saying "allowed" - so assert on the decision, not just on
    a clean exit.
    """
    result = run_present("--act", "4")
    assert "DENY" in result.stdout
    assert "was never written" in result.stdout
    # The point of the project: the agent is told what to write instead.
    assert "Do this instead" in result.stdout


def test_example_files_the_script_depends_on_exist():
    for path in (present.SCAN_REPORT, present.AGENT_DIFF, present.AGENT_WRITE):
        assert path.is_file(), f"present.py points at a missing file: {path}"


def test_act_four_payload_is_a_valid_hook_call():
    """The fixture has to stay shaped like a real Claude Code PreToolUse call."""
    payload = json.loads(present.AGENT_WRITE.read_text(encoding="utf-8"))
    assert payload["tool_name"] == "Write"
    assert payload["tool_input"]["file_path"]
    assert payload["tool_input"]["content"]


def test_the_demo_payload_lives_somewhere_the_hook_skips():
    """Why the unsafe lines are in examples/ and not inline in the script.

    The guardrail runs on this repo. Were the payload inline, the hook would
    refuse to let anyone save an edit to present.py - which is a real thing
    that happened while writing it.
    """
    from sentinel.hook import should_skip

    assert should_skip(str(present.AGENT_WRITE))
