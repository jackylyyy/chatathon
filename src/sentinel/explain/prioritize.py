"""Ranking.

A scanner ranks by severity, which is a property of the vulnerability class.
We rank by what the explanation revealed about *this* instance: how easy it
actually is to exploit here, how much it would cost if someone did, and how
cheap the fix is. That reordering is the whole point - it is what turns 40
findings into "fix these three today".
"""

from __future__ import annotations

from ..models import ExplainedFinding

# Weights sum to 1.0. Tuned so a "high" finding that is hard to reach ranks
# below a "medium" one that is trivially exploitable and cheap to fix.
W_SEVERITY = 0.35
W_LIKELIHOOD = 0.30
W_BLAST = 0.25
W_EFFORT = 0.10

_EFFORT_BONUS = {"quick": 1.0, "moderate": 0.5, "involved": 0.15}


def score(item: ExplainedFinding) -> float:
    """0-100. Higher means fix it sooner."""
    sev = item.finding.severity.rank / 5.0
    likelihood = item.explanation.exploit_likelihood / 5.0
    blast = item.explanation.blast_radius / 5.0
    effort = _EFFORT_BONUS.get(item.explanation.fix_effort, 0.5)

    raw = (
        W_SEVERITY * sev
        + W_LIKELIHOOD * likelihood
        + W_BLAST * blast
        + W_EFFORT * effort
    )
    return round(raw * 100, 1)


def prioritize(items: list[ExplainedFinding]) -> list[ExplainedFinding]:
    """Score, sort, and stamp a rank. Returns a new list."""
    for item in items:
        item.priority = score(item)

    ordered = sorted(
        items,
        key=lambda i: (-i.priority, -i.finding.severity.rank, i.finding.location),
    )
    for position, item in enumerate(ordered, start=1):
        item.rank = position
    return ordered


def triage_bucket(item: ExplainedFinding) -> str:
    """A label a human can act on without reading the score."""
    if item.priority >= 75:
        return "fix now"
    if item.priority >= 55:
        return "fix this sprint"
    if item.priority >= 35:
        return "backlog"
    return "note only"
