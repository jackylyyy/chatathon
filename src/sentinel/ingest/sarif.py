"""Parse SARIF 2.1.0.

SARIF is the common output format for SAST tools - Snyk Code, CodeQL, Semgrep,
Bandit and most others can emit it. Supporting it is what makes the explainer
tool-agnostic rather than Snyk-specific.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..models import Finding, Severity


def looks_like_sarif(payload: Any) -> bool:
    return isinstance(payload, dict) and isinstance(payload.get("runs"), list)


def parse_sarif(payload: Any) -> list[Finding]:
    if not isinstance(payload, dict):
        return []

    out: list[Finding] = []
    for run in payload.get("runs") or []:
        # `or {}` rather than a .get() default: a tool block with an explicit
        # null driver is valid JSON, and the default only applies to a missing
        # key - not a present-but-null one.
        tool_name = (
            ((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif"
        ).lower()
        rules = _index_rules(run)

        for result in run.get("results") or []:
            out.append(_to_finding(result, rules, tool_name))
    return out


def _index_rules(run: dict) -> dict[str, dict]:
    driver = (run.get("tool") or {}).get("driver") or {}
    indexed: dict[str, dict] = {}
    for rule in driver.get("rules") or []:
        if rule.get("id"):
            indexed[rule["id"]] = rule
    return indexed


def _to_finding(result: dict, rules: dict[str, dict], tool: str) -> Finding:
    rule_id = result.get("ruleId") or "unknown"
    rule = rules.get(rule_id, {})

    file_path, line, snippet = _location(result)
    severity = _severity(result, rule)

    title = (
        (rule.get("shortDescription") or {}).get("text")
        or (result.get("message") or {}).get("text")
        or rule_id
    )
    description = (
        (rule.get("fullDescription") or {}).get("text")
        or (result.get("message") or {}).get("text")
    )

    key = f"{rule_id}|{file_path}|{line}"
    finding_id = f"{tool}:{hashlib.sha1(key.encode()).hexdigest()[:10]}"

    return Finding(
        id=finding_id,
        source=tool,
        category="code",
        title=title.strip().rstrip("."),
        severity=severity,
        file=file_path,
        line=line,
        snippet=snippet,
        rule_id=rule_id,
        cwe=_tags(rule, prefix="CWE-"),
        description=description,
        raw=result,
    )


def _location(result: dict) -> tuple[str | None, int | None, str | None]:
    locations = result.get("locations") or []
    if not locations:
        return None, None, None

    physical = (locations[0] or {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}

    path = artifact.get("uri")
    if path and path.startswith("file://"):
        path = path[len("file://") :]

    line = region.get("startLine")
    snippet = ((region.get("snippet") or {}).get("text") or "").strip() or None
    return path, line, snippet


def _severity(result: dict, rule: dict) -> Severity:
    # SARIF has three places severity can hide; check the most specific first.
    props = result.get("properties") or {}
    if props.get("problem.severity"):
        return Severity.parse(props["problem.severity"])

    rule_props = rule.get("properties") or {}
    if rule_props.get("security-severity"):
        try:
            return Severity.parse(float(rule_props["security-severity"]))
        except (TypeError, ValueError):
            pass
    if rule_props.get("problem.severity"):
        return Severity.parse(rule_props["problem.severity"])

    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return Severity.parse(level or "medium")


def _tags(rule: dict, prefix: str) -> list[str]:
    tags = ((rule.get("properties") or {}).get("tags")) or []
    return [t for t in tags if isinstance(t, str) and t.upper().startswith(prefix.upper())]
