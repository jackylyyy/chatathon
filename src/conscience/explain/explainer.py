"""The shared core: Finding -> Explanation.

Both front ends go through here. `conscience explain` runs it over a scan
report; `conscience guard` runs it over findings pulled out of a diff before
the diff is applied. Nothing else in the codebase talks to the model.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..config import Settings
from ..llm import ClaudeClient, LLMUnavailable
from ..models import ExplainedFinding, Explanation, Finding
from .prioritize import prioritize
from .prompts import EXPLAINER_SYSTEM, GUARD_SYSTEM, build_explain_prompt

log = logging.getLogger(__name__)

CONTEXT_LINES = 12


class Explainer:
    def __init__(
        self,
        settings: Settings | None = None,
        client: ClaudeClient | None = None,
        *,
        guard_mode: bool = False,
    ):
        self.settings = settings or Settings.from_env()
        model = self.settings.guard_model if guard_mode else self.settings.model
        self.client = client or ClaudeClient(self.settings, model=model)
        self.system = GUARD_SYSTEM if guard_mode else EXPLAINER_SYSTEM
        self._cache: dict[str, Explanation] = {}

    # -- public API ---------------------------------------------------------

    def explain(self, finding: Finding, repo_root: Path | None = None) -> Explanation:
        if finding.id in self._cache:
            return self._cache[finding.id]

        context = _read_context(finding, repo_root)
        prompt = build_explain_prompt(finding, context)

        try:
            explanation = self.client.structured(
                system=self.system,
                user=prompt,
                output_model=Explanation,
            )
            explanation.generated_by = self.client.model
        except LLMUnavailable as exc:
            log.debug("falling back to offline explanation for %s: %s", finding.id, exc)
            explanation = offline_explanation(finding)

        self._cache[finding.id] = explanation
        return explanation

    def explain_all(
        self,
        findings: list[Finding],
        repo_root: Path | None = None,
        *,
        max_workers: int = 6,
        on_done=None,
    ) -> list[ExplainedFinding]:
        """Explain every finding, then rank them. Calls are independent, so fan out."""
        if not findings:
            return []

        def work(finding: Finding) -> ExplainedFinding:
            item = ExplainedFinding(
                finding=finding, explanation=self.explain(finding, repo_root)
            )
            if on_done is not None:
                on_done(item)
            return item

        workers = 1 if not self.client.available else min(max_workers, len(findings))
        if workers == 1:
            results = [work(f) for f in findings]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(work, findings))

        return prioritize(results)


# -- offline fallback -------------------------------------------------------


def offline_explanation(finding: Finding) -> Explanation:
    """A deterministic explanation built from the finding itself.

    Not as good as the model - but it means `conscience` works with no API key,
    on a plane, and in CI where the key is not wired up yet. It also gives the
    model-backed path something to be visibly better than.
    """
    known = _rule_knowledge(finding.rule_id)

    if finding.category == "dependency" and finding.package:
        return _dependency_explanation(finding)

    headline = known.get("headline") or f"{finding.title} in {finding.location}"
    what = known.get("what_it_means") or (
        finding.description
        or f"{finding.title}. The scanner flagged this pattern as unsafe."
    )
    attack = known.get("attack_scenario") or (
        "An attacker who controls any value reaching this line can influence what "
        "the program does with it. Without seeing the calling code we cannot say "
        "how far that reaches, so treat the input as hostile until proven otherwise."
    )

    return Explanation(
        headline=headline,
        what_it_means=what,
        attack_scenario=attack,
        why_here=(
            f"This is at {finding.location}. Trace which callers can reach it and "
            "whether any of them pass data that originally came from a user."
        ),
        fix_summary=known.get("fix_summary", "Replace the unsafe pattern with a safe equivalent."),
        fix_steps=known.get(
            "fix_steps",
            [
                f"Open {finding.location} and find the flagged line.",
                "Identify where the value comes from and whether a user can influence it.",
                "Replace the unsafe call with the safe alternative for your language.",
                "Add a test that feeds a hostile value through the same path.",
            ],
        ),
        safer_pattern=known.get("safer_pattern"),
        exploit_likelihood=known.get("exploit_likelihood", _likelihood_from_severity(finding)),
        blast_radius=known.get("blast_radius", _likelihood_from_severity(finding)),
        fix_effort=known.get("fix_effort", "moderate"),
        generated_by="offline",
    )


def _dependency_explanation(finding: Finding) -> Explanation:
    pkg = finding.package or "the package"
    version = finding.version or "the installed version"
    cve = ", ".join(finding.cve) if finding.cve else "a known vulnerability"

    if finding.fixed_in:
        fix_summary = f"Upgrade {pkg} to {finding.fixed_in} or later."
        steps = [
            f"Bump {pkg} from {version} to {finding.fixed_in} in your manifest.",
            "Reinstall and re-run the test suite.",
            "Check the package changelog between the two versions for breaking changes.",
        ]
        effort = "quick"
    else:
        fix_summary = f"No fixed version of {pkg} exists yet - you need a workaround."
        steps = [
            f"Check whether your code actually calls the vulnerable part of {pkg}.",
            "If it does, guard the call site or pin to a version without the feature.",
            f"Subscribe to the {pkg} advisory so you hear when a patch ships.",
        ]
        effort = "involved"

    return Explanation(
        headline=f"{pkg} {version} carries {cve}.",
        what_it_means=(
            f"You depend on {pkg} at {version}, and that version has a publicly "
            f"documented flaw ({cve}). Public means the details - often including "
            "working exploit code - are available to anyone."
        ),
        attack_scenario=(
            finding.description
            or f"An attacker identifies that your service ships {pkg} {version}, looks up "
            f"{cve}, and runs the published proof of concept against you. No original "
            "research required."
        ),
        why_here=(
            f"{pkg} is in your dependency tree, so it ships to production whether or "
            "not your own code touches it directly. Confirm whether you call the "
            "affected function before deciding how urgent this is."
        ),
        fix_summary=fix_summary,
        fix_steps=steps,
        # A published CVE means the research is already done, so nudge
        # likelihood up - but not to the ceiling, or every dependency finding
        # ranks identically and the ordering stops carrying information. The
        # model-backed path is what actually separates reachable from not.
        exploit_likelihood=min(5, finding.severity.rank + (1 if finding.cve else 0)),
        blast_radius=_likelihood_from_severity(finding),
        fix_effort=effort,
        generated_by="offline",
    )


def _likelihood_from_severity(finding: Finding) -> int:
    return max(1, min(5, finding.severity.rank))


def _rule_knowledge(rule_id: str | None) -> dict:
    """Guard rules carry their own hand-written explanation as a fallback."""
    if not rule_id:
        return {}
    from ..guard.rules import RULES_BY_ID  # lazy: avoids an import cycle

    rule = RULES_BY_ID.get(rule_id)
    return dict(rule.offline_explanation) if rule else {}


def _read_context(finding: Finding, repo_root: Path | None) -> str | None:
    """Pull a few lines around the finding so the model can be specific."""
    if not finding.file or not finding.line:
        return None
    path = Path(finding.file)
    if repo_root is not None and not path.is_absolute():
        path = repo_root / path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    start = max(0, finding.line - 1 - CONTEXT_LINES)
    end = min(len(lines), finding.line + CONTEXT_LINES)
    numbered = [
        f"{n:>5} | {lines[n - 1]}{'   <-- flagged' if n == finding.line else ''}"
        for n in range(start + 1, end + 1)
    ]
    return "\n".join(numbered)
