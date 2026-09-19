"""The landing page is not allowed to invent anything.

`index.html` advertises the guardrail: how many rules it has, what they catch,
what the before/after looks like. All of that is generated out of the installed
package by `scripts/sync_site.py`, and these tests are the reason that stays
true - they fail if someone edits the ruleset and forgets to regenerate, or
hand-edits the page into saying something the code does not do.

The specific failure being guarded against is quiet: a site claiming a rule
that does not exist still looks fine.
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SITE = REPO_ROOT / "index.html"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sync_site  # noqa: E402

from sentinel.guard.diff import synthesize_diff  # noqa: E402
from sentinel.guard.engine import scan_diff  # noqa: E402
from sentinel.guard.rules import RULES, RULES_BY_ID  # noqa: E402


@pytest.fixture(scope="module")
def page() -> str:
    return SITE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def payload(page: str) -> dict:
    match = re.search(
        r'<script id="sentinel-data" type="application/json">\s*(.*?)\s*</script>',
        page,
        re.DOTALL,
    )
    assert match, "index.html has no <script id='sentinel-data'> block"
    # render_block escapes `</` as `<\/` so a rule regex cannot end the script
    # element early. That is a no-op to a JSON parser, but json.loads rejects
    # the unknown `\/`... it does not, actually - `\/` is valid JSON. Parse it
    # straight and assert the escaping happened.
    assert "</" not in match.group(1), "generated JSON must escape </ as <\\/"
    return json.loads(match.group(1))


def _snippet(page: str, element_id: str) -> str:
    match = re.search(
        rf'<pre[^>]*id="{element_id}"[^>]*>(.*?)</pre>', page, re.DOTALL
    )
    assert match, f"index.html has no <pre id='{element_id}'>"
    return html.unescape(match.group(1))


# -- the page matches the package -------------------------------------------


def test_committed_page_is_in_sync_with_the_ruleset():
    """The --check path. This is the one that fails in CI after a rule edit."""
    assert sync_site.main(["--check"]) == 0, (
        "index.html is stale. Run: python scripts/sync_site.py"
    )


def test_rule_count_matches_the_shipped_ruleset(payload: dict):
    assert payload["ruleCount"] == len(RULES)
    assert len(payload["rules"]) == len(RULES)


def test_test_count_matches_what_pytest_collects(payload: dict):
    # Not a tautology against sync_site's own counter: pytest is collecting
    # this very module, so a drift between the AST count and real collection
    # shows up as a mismatch the next time either changes.
    assert payload["testCount"] == sync_site.count_tests()


def test_every_advertised_rule_exists_in_the_package(payload: dict):
    for rule in payload["rules"]:
        assert rule["id"] in RULES_BY_ID, f"site lists unknown rule {rule['id']}"
        shipped = RULES_BY_ID[rule["id"]]
        assert rule["name"] == shipped.name
        assert rule["severity"] == shipped.severity.value
        assert rule["pattern"] == shipped.pattern.pattern


def test_featured_cases_carry_a_real_before_and_after(payload: dict):
    assert payload["cases"], "the correction stream would render empty"
    for case in payload["cases"]:
        assert case["id"] in RULES_BY_ID
        assert case["unsafe"].strip(), f"{case['id']} has no unsafe example"
        assert case["safe"].strip(), f"{case['id']} has no safer pattern"


@pytest.mark.parametrize("field", ["verdict", "fixSummary", "plain"])
def test_featured_cases_have_prose_in_every_slot(payload: dict, field: str):
    """The stream renders these unconditionally, so a blank one is a blank card."""
    for case in payload["cases"]:
        assert case[field].strip(), f"{case['id']} has an empty {field}"


def test_rule_ids_named_in_the_markup_exist(page: str):
    for rule_id in re.findall(r'data-rule-id="([^"]+)"', page):
        assert rule_id in RULES_BY_ID, f"markup names unknown rule {rule_id}"


# -- the hero demo is a real interception -----------------------------------


def test_hero_unsafe_snippet_is_actually_caught(page: str):
    findings, _ = scan_diff(synthesize_diff("hero.py", _snippet(page, "hero-unsafe")))
    assert "code.python-eval-exec" in {f.rule_id for f in findings}


def test_hero_safe_snippet_is_actually_clean(page: str):
    """The corrected half has to survive the guardrail, or the demo is a lie."""
    findings, _ = scan_diff(synthesize_diff("hero.py", _snippet(page, "hero-safe")))
    assert not findings, f"the 'corrected' hero snippet still trips {findings}"


# -- the page cannot go back to rendering nothing ---------------------------


def test_page_reads_the_block_it_ships(page: str):
    """Guards the exact regression this file was written after: the reader and
    the generated block disagreeing on the element id, which silently renders
    an empty ruleset instead of failing."""
    assert 'getElementById("sentinel-data")' in page


def test_generated_markers_are_present(page: str):
    assert sync_site.BEGIN in page
    assert sync_site.END in page


# -- 04 / Demo, the interactive walkthrough ---------------------------------
#
# The walkthrough renders entirely from the generated payload, so the failure
# it is exposed to is a quiet one: a rule loses a field, and one of the five
# steps renders as a heading over blank space. Nothing else on the page would
# notice.


def test_the_demo_can_be_opened_and_has_somewhere_to_render(page: str):
    """The nav button and the element ids demo() looks up must both exist.

    Renaming one of these does not throw anywhere a test would see it - the
    button just stops doing anything.
    """
    assert "data-demo-open" in page, "nothing on the page opens the walkthrough"
    for element_id in ("demo-scrim", "demo-modal", "demo-body", "demo-rail",
                       "demo-count", "demo-back", "demo-next", "demo-close"):
        assert f'id="{element_id}"' in page, f"demo() queries #{element_id}, markup has no such id"
        assert f'getElementById("{element_id}")' in page, f"#{element_id} is in the markup but unused"


def test_every_featured_case_can_fill_all_five_steps(payload: dict):
    """Step 3 prints the pattern and severity; step 4 prints the fix steps."""
    for case in payload["cases"]:
        assert case["pattern"].strip(), f"{case['id']} has no pattern for step 3"
        assert case["severity"].strip(), f"{case['id']} has no severity for step 3"
        assert case["category"].strip(), f"{case['id']} has no category for step 3"
        assert case["fixSteps"], f"{case['id']} has no fixSteps - step 4 renders an empty list"
        for entry in case["fixSteps"]:
            assert entry.strip()


def test_the_unsafe_code_each_case_shows_really_trips_that_rule(payload: dict):
    """Step 2 claims this is what gets caught. Step 3 names the rule."""
    for case in payload["cases"]:
        findings, _ = scan_diff(synthesize_diff("demo.py", case["unsafe"]))
        assert case["id"] in {f.rule_id for f in findings}, (
            f"the walkthrough shows {case['unsafe']!r} being caught by "
            f"{case['id']}, but the guardrail does not flag it"
        )


def test_the_rewrite_each_case_ends_on_is_actually_clean(payload: dict):
    """Step 5 says this is the edit that lands. It has to survive the guardrail."""
    for case in payload["cases"]:
        findings, _ = scan_diff(synthesize_diff("demo.py", case["safe"]))
        assert not findings, (
            f"{case['id']} offers a 'safer pattern' that still trips "
            f"{[f.rule_id for f in findings]}"
        )
