"""Scan-report ingestion.

Add a new scanner by writing a `looks_like_x` / `parse_x` pair and registering
it below. Nothing downstream needs to know which tool produced a finding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..models import Finding
from .sarif import looks_like_sarif, parse_sarif
from .snyk import looks_like_snyk, parse_snyk

Parser = tuple[str, Callable[[Any], bool], Callable[[Any], list[Finding]]]

PARSERS: list[Parser] = [
    ("snyk", looks_like_snyk, parse_snyk),
    ("sarif", looks_like_sarif, parse_sarif),
]


class UnknownReportFormat(ValueError):
    pass


def detect_format(payload: Any) -> str:
    for name, matches, _ in PARSERS:
        if matches(payload):
            return name
    raise UnknownReportFormat(
        "unrecognized scan report - expected Snyk JSON (`snyk test --json`) "
        "or SARIF 2.1.0"
    )


def load_findings(path: str | Path) -> tuple[list[Finding], str]:
    """Read a scan report from disk. Returns (findings, detected format)."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_findings(payload)


def parse_findings(payload: Any) -> tuple[list[Finding], str]:
    fmt = detect_format(payload)
    parser = next(p for name, _, p in PARSERS if name == fmt)
    return parser(payload), fmt


__all__ = [
    "UnknownReportFormat",
    "detect_format",
    "load_findings",
    "parse_findings",
]
