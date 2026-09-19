from pathlib import Path

import pytest

from conscience.config import Settings
from conscience.explain.explainer import Explainer, offline_explanation
from conscience.explain.prioritize import prioritize, triage_bucket
from conscience.ingest import UnknownReportFormat, load_findings, parse_findings
from conscience.models import ExplainedFinding, Finding, Severity

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "SnykCode",
                    "rules": [
                        {
                            "id": "python/SqlInjection",
                            "shortDescription": {"text": "SQL Injection"},
                            "properties": {
                                "tags": ["security", "CWE-89"],
                                "security-severity": "8.6",
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python/SqlInjection",
                    "message": {"text": "Unsanitized input flows into execute()."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/api/reports.py"},
                                "region": {
                                    "startLine": 22,
                                    "snippet": {"text": "cur.execute(f\"...{uid}\")"},
                                },
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_snyk_report_parses():
    findings, fmt = load_findings(EXAMPLES / "snyk-report.json")

    assert fmt == "snyk"
    assert len(findings) == 5
    jwt = next(f for f in findings if f.package == "jsonwebtoken")
    assert jwt.severity is Severity.CRITICAL
    assert jwt.fixed_in == "9.0.0"
    assert jwt.cve == ["CVE-2022-23540"]
    assert jwt.category == "dependency"
    # The long markdown description is trimmed at the references section.
    assert "## References" not in (jwt.description or "")


def test_sarif_parses_with_severity_from_security_severity():
    findings, fmt = parse_findings(SARIF)

    assert fmt == "sarif"
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "snykcode"
    assert finding.severity is Severity.HIGH
    assert finding.location == "src/api/reports.py:22"
    assert finding.cwe == ["CWE-89"]


def test_unknown_format_is_rejected():
    with pytest.raises(UnknownReportFormat):
        parse_findings({"something": "else"})


def test_offline_explanation_is_populated_for_a_dependency():
    findings, _ = load_findings(EXAMPLES / "snyk-report.json")
    explanation = offline_explanation(findings[0])

    assert explanation.headline
    assert explanation.attack_scenario
    assert explanation.fix_steps
    assert explanation.generated_by == "offline"


def test_offline_explanation_uses_rule_knowledge_when_available():
    finding = Finding(
        id="x",
        source="guard",
        title="eval",
        rule_id="code.python-eval-exec",
        severity=Severity.CRITICAL,
    )
    explanation = offline_explanation(finding)

    assert "runs a string as Python code" in explanation.headline
    assert explanation.safer_pattern


def test_explainer_falls_back_without_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    findings, _ = load_findings(EXAMPLES / "snyk-report.json")

    items = Explainer(Settings(offline=True)).explain_all(findings)

    assert len(items) == len(findings)
    assert all(i.explanation.generated_by == "offline" for i in items)
    assert [i.rank for i in items] == list(range(1, len(items) + 1))


def test_prioritize_puts_the_easy_high_impact_finding_first():
    def make(sev, likelihood, blast, effort, name):
        finding = Finding(id=name, source="t", title=name, severity=sev)
        explanation = offline_explanation(finding)
        explanation.exploit_likelihood = likelihood
        explanation.blast_radius = blast
        explanation.fix_effort = effort
        return ExplainedFinding(finding=finding, explanation=explanation)

    unreachable = make(Severity.HIGH, 1, 1, "involved", "unreachable")
    trivial = make(Severity.MEDIUM, 5, 5, "quick", "trivial")

    ordered = prioritize([unreachable, trivial])

    assert ordered[0].finding.id == "trivial"
    assert triage_bucket(ordered[0]) in {"fix now", "fix this sprint"}
    assert ordered[0].priority > ordered[1].priority
