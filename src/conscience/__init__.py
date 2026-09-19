"""conscience - the understand-and-prevent layer for AI-written code.

Two front ends, one core:

    explain   a scan report (Snyk / SARIF) -> plain-English, prioritized briefing
    guard     a proposed diff -> allow / warn / block, plus feedback for the agent

Both go through `conscience.explain.Explainer`, which is the only thing that
talks to the model.
"""

from .config import DEFAULT_MODEL, Settings
from .models import (
    Explanation,
    ExplainedFinding,
    Finding,
    Severity,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_MODEL",
    "Explanation",
    "ExplainedFinding",
    "Finding",
    "Settings",
    "Severity",
    "Verdict",
    "__version__",
]
