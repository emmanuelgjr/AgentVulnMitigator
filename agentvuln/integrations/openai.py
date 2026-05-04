"""OpenAI SDK integration.

Wraps `client.chat.completions.create(...)` so every user/system message
gets scanned before the request, and the assistant's reply gets scanned
before it leaves your code.

Usage:

    from openai import OpenAI
    from agentvuln import Guard
    from agentvuln.integrations.openai import GuardedOpenAI

    client = GuardedOpenAI(OpenAI(), guard=Guard())
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": user_input}],
    )

If any message trips the policy, `GuardError` is raised before the API
call is made — no spend, no log line on OpenAI's side.
"""
from __future__ import annotations

from typing import Any

from ..guard import Action, Guard, GuardError


class _GuardedChatCompletions:
    def __init__(self, inner: Any, guard: Guard) -> None:
        self._inner = inner
        self._guard = guard

    def create(self, *args: Any, **kwargs: Any) -> Any:
        for msg in kwargs.get("messages", []) or []:
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, str):
                continue
            decision = self._guard.scan_input(content)
            if decision.action is Action.BLOCK:
                raise GuardError(
                    f"input blocked by Guard ({msg.get('role', '?')} message)",
                    decision.findings,
                )
            if decision.action is Action.REDACT and decision.redacted is not None:
                msg["content"] = decision.redacted

        response = self._inner.create(*args, **kwargs)

        for choice in getattr(response, "choices", []) or []:
            message = getattr(choice, "message", None)
            content = getattr(message, "content", None) if message is not None else None
            if not isinstance(content, str):
                continue
            decision = self._guard.scan_output(content)
            if decision.action is Action.BLOCK:
                raise GuardError("output blocked by Guard", decision.findings)
            if decision.action is Action.REDACT and decision.redacted is not None:
                try:
                    message.content = decision.redacted
                except AttributeError:
                    pass

        return response


class _GuardedChat:
    def __init__(self, inner: Any, guard: Guard) -> None:
        self.completions = _GuardedChatCompletions(inner.completions, guard)


class GuardedOpenAI:
    """Drop-in proxy around an `openai.OpenAI` client.

    Only `client.chat.completions.create(...)` is intercepted today;
    everything else passes through via `__getattr__`.
    """

    def __init__(self, client: Any, guard: Guard | None = None) -> None:
        self._client = client
        self._guard = guard or Guard()
        self.chat = _GuardedChat(client.chat, self._guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
