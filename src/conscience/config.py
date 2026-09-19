"""Runtime settings. Everything has a default so the demo runs with zero setup."""

from __future__ import annotations

import os
from dataclasses import dataclass

# Claude Opus 5 is the current top model. Thinking is on by default; don't
# pass `budget_tokens` (removed on this model - it returns a 400).
DEFAULT_MODEL = "claude-opus-5"

# Guardrail is latency-sensitive: it runs before every agent edit is applied.
DEFAULT_GUARD_MODEL = "claude-opus-5"


@dataclass(frozen=True)
class Settings:
    model: str = DEFAULT_MODEL
    guard_model: str = DEFAULT_GUARD_MODEL
    offline: bool = False
    max_tokens: int = 8000

    @classmethod
    def from_env(cls, *, offline: bool | None = None) -> "Settings":
        env_offline = os.environ.get("CONSCIENCE_OFFLINE", "").lower() in {"1", "true", "yes"}
        return cls(
            model=os.environ.get("CONSCIENCE_MODEL", DEFAULT_MODEL),
            guard_model=os.environ.get("CONSCIENCE_GUARD_MODEL", DEFAULT_GUARD_MODEL),
            offline=env_offline if offline is None else offline,
            max_tokens=int(os.environ.get("CONSCIENCE_MAX_TOKENS", "8000")),
        )


def has_credentials() -> bool:
    """The SDK also accepts an `ant auth login` profile, so an unset key is not
    proof that we can't call the API - but for a demo this check is enough to
    decide whether to try."""
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        or os.environ.get("ANTHROPIC_PROFILE")
    )
