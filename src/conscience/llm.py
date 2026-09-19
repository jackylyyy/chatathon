"""Thin wrapper around the Anthropic SDK.

One job: take a system prompt + a user prompt + a Pydantic model, and return a
validated instance of that model. If anything goes wrong - no credentials, old
SDK, rate limit, network - it raises `LLMUnavailable` and the caller falls back
to a deterministic offline explanation. The demo must never hard-fail.
"""

from __future__ import annotations

import logging
from typing import TypeVar

from pydantic import BaseModel

from .config import Settings, has_credentials

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMUnavailable(RuntimeError):
    """Raised when we could not get a structured answer out of the model."""


class ClaudeClient:
    def __init__(self, settings: Settings | None = None, model: str | None = None):
        self.settings = settings or Settings.from_env()
        self.model = model or self.settings.model
        self._client = None
        self._disabled_reason: str | None = None

        if self.settings.offline:
            self._disabled_reason = "offline mode requested"
        elif not has_credentials():
            self._disabled_reason = "no ANTHROPIC_API_KEY in the environment"

    @property
    def available(self) -> bool:
        return self._disabled_reason is None

    @property
    def unavailable_reason(self) -> str | None:
        return self._disabled_reason

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise LLMUnavailable("the `anthropic` package is not installed") from exc
        self._client = anthropic.Anthropic()
        return self._client

    def structured(
        self,
        *,
        system: str,
        user: str,
        output_model: type[T],
        max_tokens: int | None = None,
    ) -> T:
        """One non-streaming request, validated into `output_model`."""
        if not self.available:
            raise LLMUnavailable(self._disabled_reason or "model unavailable")

        import anthropic

        client = self._ensure_client()
        if not hasattr(client.messages, "parse"):
            raise LLMUnavailable(
                "this version of the anthropic SDK has no messages.parse(); "
                "upgrade with `pip install -U anthropic`"
            )

        try:
            response = client.messages.parse(
                model=self.model,
                max_tokens=max_tokens or self.settings.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_format=output_model,
            )
        except anthropic.AuthenticationError as exc:
            raise LLMUnavailable("the API key was rejected") from exc
        except anthropic.NotFoundError as exc:
            raise LLMUnavailable(f"model {self.model!r} was not found") from exc
        except anthropic.RateLimitError as exc:
            raise LLMUnavailable("rate limited") from exc
        except anthropic.APIStatusError as exc:
            raise LLMUnavailable(f"API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMUnavailable("could not reach the API") from exc

        if response.stop_reason == "refusal":
            raise LLMUnavailable("the model declined to answer this request")

        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            raise LLMUnavailable("the model returned no structured output")
        return parsed
