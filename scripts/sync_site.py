"""Regenerate the landing page's data block from the live codebase.

The site advertises the guardrail, so the two must not drift: a rule added to
`guard/rules.py` should not need a second, hand-copied edit in `index.html`,
and a site that lists rules the code does not have is worse than no site.

This script reads the real ruleset, the real version, and the real test count,
and rewrites the single `<script id="conscience-data">` block in `index.html`.
Nothing else in the page is touched.

    python scripts/sync_site.py          # rewrite the block
    python scripts/sync_site.py --check  # exit 1 if it is out of date

`tests/test_site_sync.py` runs the --check path, so CI fails if someone edits
the ruleset and forgets to run this.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SITE = REPO_ROOT / "index.html"
TESTS = REPO_ROOT / "tests"

BEGIN = "<!-- BEGIN GENERATED: scripts/sync_site.py -->"
END = "<!-- END GENERATED -->"

# The three rules the "correction stream" section walks through. Each needs an
# `example` on its Rule, so the before/after pair comes from the ruleset.
FEATURED = (
    "code.python-eval-exec",
    "secret.hardcoded-credential",
    "code.unsafe-deserialization",
)

sys.path.insert(0, str(REPO_ROOT / "src"))


def count_tests() -> int:
    """Count test functions without importing or running pytest."""
    total = 0
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                total += 1
    return total


def build_payload() -> dict:
    from conscience import __version__
    from conscience.guard.rules import DEPENDENCY_MANIFESTS, RULES, RULES_BY_ID

    rules = []
    for rule in RULES:
        explanation = rule.offline_explanation
        rules.append(
            {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.value,
                "category": rule.category,
                "appliesTo": [ext.lstrip(".") for ext in rule.extensions] or ["any file"],
                "cwe": list(rule.cwe),
                "pattern": rule.pattern.pattern,
                "headline": explanation.get("headline", ""),
                "whatItMeans": explanation.get("what_it_means", ""),
                "fixSummary": explanation.get("fix_summary", ""),
                "saferPattern": explanation.get("safer_pattern"),
                "example": rule.example,
            }
        )

    cases = []
    for rule_id in FEATURED:
        rule = RULES_BY_ID[rule_id]
        explanation = rule.offline_explanation
        if not rule.example:
            raise SystemExit(f"featured rule {rule_id} has no `example` to show")
        cases.append(
            {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.value,
                "category": rule.category,
                "pattern": rule.pattern.pattern,
                "unsafe": rule.example,
                "safe": explanation.get("safer_pattern") or "",
                # What the guardrail tells the agent, and the longer
                # plain-English version a newcomer reads.
                "verdict": explanation.get("what_it_means", ""),
                "fixSummary": explanation.get("fix_summary", ""),
                "plain": explanation.get("attack_scenario", ""),
                "fixSteps": list(explanation.get("fix_steps", [])),
            }
        )

    return {
        "version": __version__,
        "repo": "https://github.com/jackylyyy/chatathon",
        "ruleCount": len(RULES),
        "testCount": count_tests(),
        "manifests": list(DEPENDENCY_MANIFESTS),
        "severityOrder": ["critical", "high", "medium", "low", "info"],
        "cases": cases,
        "rules": rules,
    }


def render_block(payload: dict) -> str:
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    return (
        f"{BEGIN}\n"
        '<script id="conscience-data" type="application/json">\n'
        f"{body}\n"
        "</script>\n"
        f"{END}"
    )


def splice(html: str, block: str) -> str:
    start = html.find(BEGIN)
    end = html.find(END)
    if start == -1 or end == -1:
        raise SystemExit(
            f"{SITE} has no generated block - expected the markers\n"
            f"  {BEGIN}\n  {END}"
        )
    return html[:start] + block + html[end + len(END) :]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if index.html is out of date.",
    )
    args = parser.parse_args(argv)

    current = SITE.read_text(encoding="utf-8")
    updated = splice(current, render_block(build_payload()))

    if args.check:
        if current != updated:
            print(
                "index.html is out of date with the ruleset. "
                "Run: python scripts/sync_site.py",
                file=sys.stderr,
            )
            return 1
        print("index.html is in sync with the ruleset.")
        return 0

    if current == updated:
        print("index.html already in sync, nothing written.")
        return 0

    SITE.write_text(updated, encoding="utf-8")
    print(f"Wrote {SITE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
