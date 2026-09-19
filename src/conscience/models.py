"""Core data model shared by both front ends.

Everything upstream (a Snyk report, a SARIF file, a diff an AI agent wants to
apply) normalizes into a `Finding`. Everything downstream (the CLI, the agent
feedback block, the JSON API) consumes an `ExplainedFinding`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @classmethod
    def parse(cls, raw: Any) -> "Severity":
        """Accept the many ways scanners spell severity."""
        if isinstance(raw, Severity):
            return raw
        if isinstance(raw, (int, float)):
            # CVSS base score
            score = float(raw)
            if score >= 9.0:
                return cls.CRITICAL
            if score >= 7.0:
                return cls.HIGH
            if score >= 4.0:
                return cls.MEDIUM
            return cls.LOW
        text = str(raw or "").strip().lower()
        aliases = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "error": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "low": cls.LOW,
            "note": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "none": cls.INFO,
        }
        return aliases.get(text, cls.MEDIUM)


Category = Literal["dependency", "code", "secret", "license", "config"]


class Finding(BaseModel):
    """One normalized security problem, wherever it came from."""

    id: str
    source: str = Field(description="snyk | sarif | guard | ...")
    category: Category = "code"
    title: str
    severity: Severity = Severity.MEDIUM

    # Where it lives
    file: str | None = None
    line: int | None = None
    snippet: str | None = None

    # Dependency findings
    package: str | None = None
    version: str | None = None
    fixed_in: str | None = None

    # Classification
    rule_id: str | None = None
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)

    description: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        if self.package:
            return f"{self.package}@{self.version}" if self.version else self.package
        return "unknown"


class Explanation(BaseModel):
    """The plain-English layer. This is the product.

    Written for a developer who is not a security person: no CVSS vectors, no
    jargon, no "sanitize untrusted input" hand-waving.
    """

    headline: str = Field(
        description="One sentence a junior developer immediately understands. No jargon."
    )
    what_it_means: str = Field(
        description="2-3 sentences: what the code/dependency actually does wrong."
    )
    attack_scenario: str = Field(
        description="A concrete story: an attacker does X, and because of Y they get Z."
    )
    why_here: str = Field(
        description="Why this matters in THIS codebase specifically, given the file and context."
    )
    fix_summary: str = Field(description="The fix in one sentence.")
    fix_steps: list[str] = Field(
        default_factory=list, description="2-5 concrete, ordered steps."
    )
    safer_pattern: str | None = Field(
        default=None, description="A short corrected code snippet, if code-level."
    )
    exploit_likelihood: int = Field(
        default=3, ge=1, le=5, description="1 = needs a lab, 5 = script kiddie today."
    )
    blast_radius: int = Field(
        default=3, ge=1, le=5, description="1 = one user's session, 5 = whole database."
    )
    fix_effort: Literal["quick", "moderate", "involved"] = "moderate"
    generated_by: str = Field(default="offline", exclude=True)


class ExplainedFinding(BaseModel):
    finding: Finding
    explanation: Explanation
    priority: float = 0.0
    rank: int = 0


class Verdict(BaseModel):
    """What the guardrail decided about a proposed change."""

    decision: Literal["allow", "warn", "block"] = "allow"
    findings: list[ExplainedFinding] = Field(default_factory=list)
    files_reviewed: list[str] = Field(default_factory=list)
    lines_reviewed: int = 0
    agent_feedback: str = ""

    @property
    def ok(self) -> bool:
        return self.decision != "block"
