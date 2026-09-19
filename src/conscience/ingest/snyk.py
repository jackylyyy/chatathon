"""Parse `snyk test --json` output (open-source / SCA findings).

Snyk emits either a single project object or a list of them when a repo has
several manifests. Both shapes land here.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..models import Finding, Severity


def looks_like_snyk(payload: Any) -> bool:
    if isinstance(payload, list):
        return any(looks_like_snyk(item) for item in payload)
    return isinstance(payload, dict) and "vulnerabilities" in payload


def parse_snyk(payload: Any) -> list[Finding]:
    if isinstance(payload, list):
        findings: list[Finding] = []
        for project in payload:
            findings.extend(parse_snyk(project))
        return findings

    if not isinstance(payload, dict):
        return []

    manifest = payload.get("displayTargetFile") or payload.get("targetFile")
    out: list[Finding] = []
    seen: set[str] = set()

    for vuln in payload.get("vulnerabilities") or []:
        finding = _to_finding(vuln, manifest)
        # Snyk reports the same vulnerability once per dependency path.
        # Collapse them: a developer fixes it once.
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)

    return out


def _to_finding(vuln: dict, manifest: str | None) -> Finding:
    identifiers = vuln.get("identifiers") or {}
    package = vuln.get("packageName") or vuln.get("name") or "unknown"
    version = vuln.get("version")

    fixed_in = vuln.get("fixedIn") or []
    fixed = fixed_in[0] if isinstance(fixed_in, list) and fixed_in else None

    severity = vuln.get("severity")
    if severity is None and vuln.get("cvssScore") is not None:
        severity = vuln["cvssScore"]

    key = f"{vuln.get('id', '')}|{package}|{version}"
    finding_id = f"snyk:{hashlib.sha1(key.encode()).hexdigest()[:10]}"

    return Finding(
        id=finding_id,
        source="snyk",
        category="dependency",
        title=vuln.get("title") or f"Vulnerability in {package}",
        severity=Severity.parse(severity),
        file=manifest,
        package=package,
        version=version,
        fixed_in=fixed,
        rule_id=vuln.get("id"),
        cve=list(identifiers.get("CVE") or []),
        cwe=list(identifiers.get("CWE") or []),
        description=_clean(vuln.get("description")),
        raw=vuln,
    )


def _clean(text: str | None, limit: int = 1500) -> str | None:
    """Snyk descriptions are long markdown documents. Keep the useful head."""
    if not text:
        return None
    text = text.strip()
    # Drop the repeated "## Overview" heading and the reference dump at the end.
    for marker in ("## References", "## Remediation"):
        idx = text.find(marker)
        if idx > 0:
            text = text[:idx]
    return text[:limit].strip()
