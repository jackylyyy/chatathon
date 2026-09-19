"""Runtime settings. Everything has a default so the demo runs with zero setup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Claude Opus 5 is the current top model. Thinking is on by default; don't
# pass `budget_tokens` (removed on this model - it returns a 400).
DEFAULT_MODEL = "claude-opus-5"

# Guardrail is latency-sensitive: it runs before every agent edit is applied.
DEFAULT_GUARD_MODEL = "claude-opus-5"


def load_dotenv(start: Path | None = None) -> Path | None:
    """Read the nearest `.env` into the environment. Returns the file used.

    The README tells people to put ANTHROPIC_API_KEY in `.env`, so something
    has to actually read it - otherwise the key is set, nothing picks it up,
    and the tool silently serves offline explanations with no hint why.

    A real environment variable always wins, so exporting a key still
    overrides the file.
    """
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / ".env"
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].lstrip()
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value
        return candidate
    return None


load_dotenv()


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
