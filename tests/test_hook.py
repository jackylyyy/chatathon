"""Hook contract tests.

Three properties keep this thing usable, and all three are easy to break:
  - it denies dangerous NEW code
  - it never blames the agent for code that was already there
  - it fails open, always
"""

import io
import json

import pytest

from conscience import hook as hookmod
from conscience.hook import (
    REVIEWABLE_TOOLS,
    NotReviewable,
    build_diff,
    main,
    proposed_content,
    review,
    should_skip,
)

DANGEROUS = 'import jwt\nclaims = jwt.decode(token, options={"verify_signature": False})\n'
SAFE = "def add(a, b):\n    return a + b\n"


def payload(tool_name="Write", cwd=".", **tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": tool_name, "cwd": str(cwd),
            "tool_input": tool_input}


# -- what gets reviewed at all ----------------------------------------------


@pytest.mark.parametrize("path", [
    "tests/test_auth.py",
    "src/__tests__/thing.js",
    "examples/sample.py",
    "node_modules/pkg/index.js",
    ".venv/lib/site-packages/x.py",
    "src/conftest.py",
    "src/app.spec.ts",
])
def test_fixture_and_vendor_paths_are_skipped(path):
    assert should_skip(path)


@pytest.mark.parametrize("path", ["src/api/login.py", "app.js", "src/latest/main.py"])
def test_real_source_paths_are_reviewed(path):
    assert not should_skip(path)


def test_only_code_writing_tools_are_reviewed():
    assert REVIEWABLE_TOOLS == {"Write", "Edit", "MultiEdit"}

    response, log = review(payload(tool_name="Bash", command="ls"))

    assert response is None
    assert "not a code-writing tool" in log


# -- reconstructing the change ----------------------------------------------


def test_write_to_a_new_file_is_all_additions(tmp_path):
    path, before, after = proposed_content(
        "Write", {"file_path": "new.py", "content": SAFE}, tmp_path
    )

    assert before == ""
    assert after == SAFE
    assert path == tmp_path / "new.py"


def test_edit_is_applied_in_memory_not_on_disk(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")

    _, before, after = proposed_content(
        "Edit", {"file_path": "app.py", "old_string": "return 1", "new_string": "return 2"},
        tmp_path,
    )

    assert "return 1" in before
    assert "return 2" in after
    # The file itself is untouched - we are judging a proposal.
    assert target.read_text(encoding="utf-8") == "def f():\n    return 1\n"


def test_multiedit_applies_every_edit(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("a = 1\nb = 2\n", encoding="utf-8")

    _, _, after = proposed_content(
        "MultiEdit",
        {"file_path": "app.py", "edits": [
            {"old_string": "a = 1", "new_string": "a = 10"},
            {"old_string": "b = 2", "new_string": "b = 20"},
        ]},
        tmp_path,
    )

    assert after == "a = 10\nb = 20\n"


def test_a_call_with_no_file_path_is_not_reviewable(tmp_path):
    with pytest.raises(NotReviewable):
        proposed_content("Write", {"content": "x"}, tmp_path)


def test_diff_of_an_unchanged_file_is_empty(tmp_path):
    assert build_diff(tmp_path / "a.py", SAFE, SAFE, tmp_path) == ""


# -- the decisions ----------------------------------------------------------


def test_dangerous_new_code_is_denied(tmp_path, monkeypatch):
    monkeypatch.setenv("CONSCIENCE_OFFLINE", "1")

    response, log = review(
        payload(cwd=tmp_path, file_path="api/login.py", content=DANGEROUS)
    )

    assert response is not None
    out = response["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    # The reason is the agent's instructions, not a status code.
    assert "Do this instead" in out["permissionDecisionReason"]
    assert "jwt.decode" in out["permissionDecisionReason"]
    assert "DENIED" in log


def test_safe_code_is_allowed_silently(tmp_path, monkeypatch):
    monkeypatch.setenv("CONSCIENCE_OFFLINE", "1")

    response, log = review(payload(cwd=tmp_path, file_path="util.py", content=SAFE))

    assert response is None
    assert "nothing flagged" in log


def test_preexisting_vulnerability_is_not_blamed_on_the_agent(tmp_path, monkeypatch):
    """The property that decides whether anyone keeps this hook installed."""
    monkeypatch.setenv("CONSCIENCE_OFFLINE", "1")
    legacy = tmp_path / "legacy.py"
    legacy.write_text(
        'password = "supersecret123"\n\ndef helper():\n    return 1\n', encoding="utf-8"
    )

    response, log = review(payload(
        tool_name="Edit", cwd=tmp_path, file_path="legacy.py",
        old_string="return 1", new_string="return 2",
    ))

    assert response is None, "a clean edit to a dirty file must not be denied"
    assert "nothing flagged" in log


def test_an_edit_that_introduces_a_vulnerability_is_denied(tmp_path, monkeypatch):
    monkeypatch.setenv("CONSCIENCE_OFFLINE", "1")
    legacy = tmp_path / "legacy.py"
    legacy.write_text("def helper():\n    return 1\n", encoding="utf-8")

    response, _ = review(payload(
        tool_name="Edit", cwd=tmp_path, file_path="legacy.py",
        old_string="    return 1",
        new_string="    subprocess.run(cmd, shell=True)\n    return 1",
    ))

    assert response is not None
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_no_op_edit_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("CONSCIENCE_OFFLINE", "1")
    target = tmp_path / "app.py"
    target.write_text(SAFE, encoding="utf-8")

    response, log = review(payload(
        tool_name="Edit", cwd=tmp_path, file_path="app.py",
        old_string="return a + b", new_string="return a + b",
    ))

    assert response is None
    assert "no net change" in log


# -- failing open -----------------------------------------------------------


def _run_main(monkeypatch, capsys, stdin_text):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    code = main([])
    return code, capsys.readouterr()


def test_garbage_input_allows_the_edit(monkeypatch, capsys):
    code, captured = _run_main(monkeypatch, capsys, "this is not json")

    assert code == 0
    assert captured.out == ""  # no decision -> normal permission flow


def test_empty_input_allows_the_edit(monkeypatch, capsys):
    code, captured = _run_main(monkeypatch, capsys, "")

    assert code == 0
    assert captured.out == ""


def test_an_internal_crash_still_allows_the_edit(monkeypatch, capsys):
    """If our own code throws, the developer must not notice."""
    def explode(*args, **kwargs):
        raise RuntimeError("simulated bug in the ruleset")

    monkeypatch.setattr(hookmod, "review", explode)

    code, captured = _run_main(
        monkeypatch, capsys,
        json.dumps(payload(file_path="api.py", content=DANGEROUS)),
    )

    assert code == 0
    assert captured.out == ""
    assert "internal error" in captured.err


def test_main_prints_valid_json_when_denying(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("CONSCIENCE_OFFLINE", "1")

    code, captured = _run_main(
        monkeypatch, capsys,
        json.dumps(payload(cwd=tmp_path, file_path="api.py", content=DANGEROUS)),
    )

    assert code == 0
    decision = json.loads(captured.out)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
