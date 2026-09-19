"""CLI contract tests.

Two properties matter enough to pin down:
  - stdout is the result and nothing else, so `--format json` stays pipeable
  - the exit code is the signal, so `guard` can gate a hook
Both were broken once; neither should break silently again.
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from conscience.cli import app

runner = CliRunner()
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
REPORT = str(EXAMPLES / "snyk-report.json")
DIFF = str(EXAMPLES / "agent-change.diff")


def test_explain_json_stdout_is_pure_json():
    result = runner.invoke(app, ["explain", REPORT, "--format", "json", "--offline"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)  # would raise if a notice leaked to stdout
    assert len(payload) == 5
    assert payload[0]["rank"] == 1
    assert payload[0]["explanation"]["headline"]


def test_explain_emits_an_empty_document_when_nothing_qualifies():
    result = runner.invoke(
        app,
        ["explain", REPORT, "--format", "json", "--min-severity", "critical",
         "--limit", "0", "--offline"],
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert [p["finding"]["package"] for p in payload] == ["jsonwebtoken"]


def test_explain_with_no_qualifying_findings_still_parses():
    empty = {"vulnerabilities": []}
    path = EXAMPLES / "_tmp_empty.json"
    path.write_text(json.dumps(empty), encoding="utf-8")
    try:
        result = runner.invoke(app, ["explain", str(path), "--format", "json", "--offline"])
        assert result.exit_code == 0
        assert json.loads(result.stdout) == []
    finally:
        path.unlink()


def test_explain_rejects_an_unknown_format_with_exit_2():
    bad = EXAMPLES / "_tmp_bad.json"
    bad.write_text('{"not": "a scan"}', encoding="utf-8")
    try:
        result = runner.invoke(app, ["explain", str(bad), "--offline"])
        assert result.exit_code == 2
    finally:
        bad.unlink()


def test_explain_missing_file_exits_2():
    result = runner.invoke(app, ["explain", "does-not-exist.json", "--offline"])

    assert result.exit_code == 2


def test_explain_writes_markdown_to_a_file(tmp_path):
    out = tmp_path / "briefing.md"
    result = runner.invoke(
        app, ["explain", REPORT, "--format", "md", "--out", str(out), "--offline"]
    )

    assert result.exit_code == 0
    written = out.read_text(encoding="utf-8")
    assert written.startswith("# Security briefing")
    assert "jsonwebtoken" in written


def test_guard_blocks_and_returns_exit_1():
    result = runner.invoke(app, ["guard", "--diff", DIFF, "--format", "json", "--offline"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["decision"] == "block"
    assert payload["agent_feedback"]


def test_guard_allows_a_clean_file_with_exit_0(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    result = runner.invoke(app, ["guard", "--file", str(clean), "--format", "json", "--offline"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["decision"] == "allow"


def test_guard_without_an_input_exits_2():
    result = runner.invoke(app, ["guard", "--offline"])

    assert result.exit_code == 2


def test_rules_lists_every_rule():
    from conscience.guard.rules import RULES

    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    assert f"{len(RULES)} rules" in result.stdout
