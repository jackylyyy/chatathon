"""The guardrail: judge a change before it is applied.

Flow: diff -> added lines -> rules -> findings -> explanations -> verdict.

The output that matters is `agent_feedback`: a markdown block written to be fed
straight back into the coding agent's context. A blocked edit with no
explanation just teaches the agent to try a variation. A blocked edit with a
named safer pattern teaches it to write the right thing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..config import Settings
from ..explain.explainer import Explainer
from ..explain.prioritize import prioritize
from ..models import Decision, ExplainedFinding, Finding, Severity, Verdict
from .diff import AddedLine, ParsedDiff, parse_unified_diff, synthesize_diff
from .rules import (
    DEPENDENCY_MANIFESTS,
    NEW_DEPENDENCY_RULE_ID,
    RULES,
    is_comment,
    is_pattern_definition,
)

# Anything at or above this severity blocks the edit.
DEFAULT_BLOCK_AT = Severity.HIGH
# Anything at or above this warns (but allows). At INFO this means: if we found
# anything at all, say so. "allow" is reserved for a genuinely clean change, so
# a caller can trust the decision without also inspecting the findings list.
DEFAULT_WARN_AT = Severity.INFO


def scan_diff(diff_text: str) -> tuple[list[Finding], ParsedDiff]:
    """Run the ruleset over every added line. No model involved - this is fast."""
    parsed = parse_unified_diff(diff_text)
    findings: list[Finding] = []

    for added in parsed.added:
        findings.extend(_scan_line(added))

    for manifest_finding in _scan_manifests(parsed.added):
        findings.append(manifest_finding)

    return _dedupe(findings), parsed


def _scan_line(added: AddedLine) -> list[Finding]:
    text = added.text
    if not text.strip() or is_comment(text) or is_pattern_definition(text):
        return []

    out: list[Finding] = []
    for rule in RULES:
        if not rule.applies_to(added.file):
            continue
        if not rule.pattern.search(text):
            continue
        if rule.requires is not None and not rule.requires.search(text):
            continue
        if rule.unless is not None and rule.unless.search(text):
            continue

        out.append(
            Finding(
                id=_finding_id(rule.id, added),
                source="guard",
                category=rule.category,
                title=rule.name,
                severity=rule.severity,
                file=added.file,
                line=added.line,
                snippet=text.strip(),
                rule_id=rule.id,
                cwe=list(rule.cwe),
            )
        )
    return out


def _scan_manifests(added: list[AddedLine]) -> list[Finding]:
    """Flag new dependencies so a human (or the trust-score layer) can look."""
    out: list[Finding] = []
    for line in added:
        name = Path(line.file).name
        if name not in DEPENDENCY_MANIFESTS:
            continue
        package = _extract_package(line.text, name)
        if not package:
            continue
        out.append(
            Finding(
                id=_finding_id("dep.new", line),
                source="guard",
                category="dependency",
                title=f"New dependency added: {package}",
                severity=Severity.INFO,
                file=line.file,
                line=line.line,
                snippet=line.text.strip(),
                rule_id=NEW_DEPENDENCY_RULE_ID,
                package=package,
                description=(
                    "A package is being added to the project. Nothing is known to be wrong "
                    "with it - this is the moment to check that it is the package you meant, "
                    "that it is actively maintained, and that the name is not a near-miss of "
                    "a more popular one."
                ),
            )
        )
    return out


def _extract_package(text: str, manifest: str) -> str | None:
    stripped = text.strip().rstrip(",")
    if not stripped:
        return None
    if manifest == "package.json":
        if ":" not in stripped or not stripped.startswith('"'):
            return None
        return stripped.split(":", 1)[0].strip().strip('"')
    if manifest in {"requirements.txt", "Pipfile"}:
        if stripped.startswith(("#", "-")):
            return None
        for sep in ("==", ">=", "<=", "~=", ">", "<", "="):
            if sep in stripped:
                return stripped.split(sep, 1)[0].strip()
        return stripped
    if manifest in {"pyproject.toml", "Cargo.toml"}:
        if "=" in stripped and not stripped.startswith("["):
            return stripped.split("=", 1)[0].strip().strip('"')
        if stripped.startswith('"'):
            return stripped.strip('"').split()[0]
    return None


def _finding_id(rule_id: str, added: AddedLine) -> str:
    digest = hashlib.sha1(
        f"{rule_id}|{added.file}|{added.line}|{added.text}".encode()
    ).hexdigest()[:10]
    return f"{rule_id}:{digest}"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return out


class Guard:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        block_at: Severity = DEFAULT_BLOCK_AT,
        explain: bool = True,
    ):
        self.settings = settings or Settings.from_env()
        self.block_at = block_at
        self.explain_findings = explain
        self._explainer = Explainer(self.settings, guard_mode=True)

    def review_diff(self, diff_text: str, repo_root: Path | None = None) -> Verdict:
        findings, parsed = scan_diff(diff_text)

        if not findings:
            return Verdict(
                decision="allow",
                files_reviewed=parsed.files,
                lines_reviewed=parsed.line_count,
                agent_feedback="",
            )

        if self.explain_findings:
            explained = self._explainer.explain_all(findings, repo_root)
        else:
            from ..explain.explainer import offline_explanation

            explained = prioritize(
                [
                    ExplainedFinding(finding=f, explanation=offline_explanation(f))
                    for f in findings
                ]
            )

        decision = self._decide(explained)
        return Verdict(
            decision=decision,
            findings=explained,
            files_reviewed=parsed.files,
            lines_reviewed=parsed.line_count,
            agent_feedback=render_agent_feedback(explained, decision),
        )

    def review_file(
        self, file: str, content: str, repo_root: Path | None = None
    ) -> Verdict:
        """For a proposed whole-file write, where there is no diff yet."""
        return self.review_diff(synthesize_diff(file, content), repo_root)

    def _decide(self, explained: list[ExplainedFinding]) -> Decision:
        worst = max((e.finding.severity.rank for e in explained), default=0)
        if worst >= self.block_at.rank:
            return "block"
        if worst >= DEFAULT_WARN_AT.rank:
            return "warn"
        return "allow"


def render_agent_feedback(findings: list[ExplainedFinding], decision: str) -> str:
    """The block that gets injected back into the coding agent's context.

    Written as an instruction to the agent, not as a report about it. Ordered
    worst-first, because a truncated context should keep the important half.
    """
    if not findings:
        return ""

    verb = "was not applied" if decision == "block" else "was applied with warnings"
    lines = [
        f"## Security review: this change {verb}",
        "",
        f"{len(findings)} issue(s) were found in the lines you added. "
        "Rewrite the change so the patterns below are gone, then try again.",
        "",
    ]

    for item in findings:
        f, e = item.finding, item.explanation
        lines.append(f"### {f.severity.value.upper()} - {f.title}")
        lines.append(f"**Where:** `{f.location}`")
        if f.snippet:
            lines.append(f"**The line you wrote:** `{f.snippet}`")
        lines.append("")
        lines.append(f"**Why this is a problem:** {e.what_it_means}")
        lines.append("")
        lines.append(f"**What an attacker does with it:** {e.attack_scenario}")
        lines.append("")
        lines.append(f"**Do this instead:** {e.fix_summary}")
        if e.safer_pattern:
            lines.append("")
            lines.append("```")
            lines.append(e.safer_pattern)
            lines.append("```")
        lines.append("")

    lines.append(
        "If you believe a finding is wrong for this context, say why explicitly "
        "instead of rewording the same code - a human is reading this too."
    )
    return "\n".join(lines)
