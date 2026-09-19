"""Prompts for the explainer core.

Design note: the audience is a developer who is NOT a security person. Every
instruction here exists to fight the default failure mode of security tooling -
technically correct output that nobody acts on because nobody understands it.
"""

from __future__ import annotations

from ..models import Finding

EXPLAINER_SYSTEM = """\
You explain security findings to working developers who are not security experts.

Your reader is competent at their job and short on time. They have seen a wall of
CVE IDs and severity scores and learned to ignore them. Your job is to make one
finding land: what it actually means, what an attacker actually does with it, and
what to actually change.

Rules:
- Write like a senior engineer explaining to a teammate at a desk, not like a report.
- No jargon without a plain-English gloss. Never say "sanitize untrusted input",
  "improper neutralization", or "leverage" - say exactly what happens.
- The attack scenario must be concrete and specific to the code you were shown.
  Name the actual function, parameter, route, or package. "An attacker could
  execute arbitrary code" is a failure; "someone pastes `; rm -rf /` into the
  `filename` field and it reaches the shell" is the standard.
- Be honest about likelihood. If the vulnerable code path is not reachable from
  user input, say so and score exploit_likelihood low. Overstating risk is how
  security tools lose their audience.
- fix_steps must be steps someone can perform, in order, today.
- If you are given a code snippet, safer_pattern must be a rewrite of THAT
  snippet, not a generic example.
- Do not invent facts about the codebase you were not shown. If you are
  reasoning from limited context, keep why_here modest.
"""

GUARD_SYSTEM = (
    EXPLAINER_SYSTEM
    + """
Additional context: this finding was caught in code an AI coding agent is about
to write, before it was applied. Your explanation will be injected back into
that agent's context so it can correct itself. So:
- Address the fix to whoever is writing the code, in the imperative.
- safer_pattern is the most important field here. Make it a drop-in replacement.
"""
)


def build_explain_prompt(finding: Finding, file_context: str | None = None) -> str:
    """Render one finding into a prompt. Stable ordering keeps the prefix cacheable."""
    lines: list[str] = ["Explain this security finding.", "", "## Finding", ""]

    lines.append(f"- Title: {finding.title}")
    lines.append(f"- Reported severity: {finding.severity.value}")
    lines.append(f"- Category: {finding.category}")
    lines.append(f"- Source tool: {finding.source}")
    if finding.rule_id:
        lines.append(f"- Rule: {finding.rule_id}")
    if finding.cwe:
        lines.append(f"- CWE: {', '.join(finding.cwe)}")
    if finding.cve:
        lines.append(f"- CVE: {', '.join(finding.cve)}")
    if finding.package:
        version = finding.version or "unknown version"
        lines.append(f"- Package: {finding.package} {version}")
        if finding.fixed_in:
            lines.append(f"- Fixed in: {finding.fixed_in}")
        else:
            lines.append("- Fixed in: no fixed version is available")
    if finding.file:
        lines.append(f"- Location: {finding.location}")
    if finding.description:
        lines.append("")
        lines.append("### Scanner description")
        lines.append(finding.description.strip())

    if finding.snippet:
        lines += ["", "### The code in question", "", "```", finding.snippet.rstrip(), "```"]

    if file_context:
        lines += [
            "",
            "### Surrounding file context",
            "",
            "```",
            file_context.rstrip(),
            "```",
        ]

    lines += [
        "",
        "Now write the explanation. Ground the attack scenario in the specific "
        "code and location above.",
    ]
    return "\n".join(lines)
