"""The fallback path is load-bearing: it is what keeps the demo alive when the
key is missing, the network is down, or the SDK is old. Its contract is that
everything failable raises LLMUnavailable and nothing else escapes.
"""

import pytest

from sentinel.config import Settings
from sentinel.explain.explainer import Explainer
from sentinel.llm import ClaudeClient, LLMUnavailable
from sentinel.models import Explanation, Finding, Severity


def a_finding() -> Finding:
    return Finding(
        id="t1",
        source="guard",
        title="eval() or exec() on a non-literal value",
        rule_id="code.python-eval-exec",
        severity=Severity.CRITICAL,
        file="app.py",
        line=3,
    )


def test_offline_client_reports_why_it_is_unavailable():
    client = ClaudeClient(Settings(offline=True))

    assert not client.available
    assert "offline" in (client.unavailable_reason or "")

    with pytest.raises(LLMUnavailable):
        client.structured(system="s", user="u", output_model=Explanation)


def test_missing_key_disables_the_client(monkeypatch):
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
        monkeypatch.delenv(var, raising=False)

    client = ClaudeClient(Settings(offline=False))

    assert not client.available
    assert "ANTHROPIC_API_KEY" in (client.unavailable_reason or "")


def test_missing_sdk_raises_llm_unavailable_not_import_error(monkeypatch):
    """A caller only catches LLMUnavailable, so an ImportError here would crash
    the fallback instead of triggering it."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = ClaudeClient(Settings(offline=False))

    import builtins

    real_import = builtins.__import__

    def no_anthropic(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("simulated missing dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_anthropic)

    with pytest.raises(LLMUnavailable):
        client.structured(system="s", user="u", output_model=Explanation)


def test_explainer_degrades_instead_of_raising(monkeypatch):
    """Whatever the model layer does, explain() must return an Explanation."""
    explainer = Explainer(Settings(offline=False))

    def always_fails(**kwargs):
        raise LLMUnavailable("simulated outage")

    monkeypatch.setattr(explainer.client, "structured", always_fails)
    monkeypatch.setattr(type(explainer.client), "available", property(lambda self: True))

    explanation = explainer.explain(a_finding())

    assert explanation.generated_by == "offline"
    assert explanation.attack_scenario
    assert explanation.safer_pattern  # came from the rule's own knowledge


def test_explanations_are_cached_per_finding(monkeypatch):
    explainer = Explainer(Settings(offline=True))
    finding = a_finding()

    first = explainer.explain(finding)
    calls = []

    def tracked(*args, **kwargs):
        calls.append(1)
        raise AssertionError("should not be re-explained")

    monkeypatch.setattr("sentinel.explain.explainer.offline_explanation", tracked)
    second = explainer.explain(finding)

    assert second is first
    assert calls == []
