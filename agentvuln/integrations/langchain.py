"""LangChain integration.

Two surfaces:

1. `guard_runnable(guard)` — a `RunnableLambda` you can chain into any
   LCEL pipeline to scan strings or message lists.

2. `GuardCallbackHandler(guard)` — a `BaseCallbackHandler` that scans
   every prompt sent to an LLM and every completion received. Drop it
   into `chain.invoke(..., config={"callbacks": [handler]})`.

Soft-imports LangChain so the rest of agentvuln runs without it.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from ..guard import Action, Guard, GuardError


def guard_runnable(guard: Guard | None = None) -> Any:
    """Return a `RunnableLambda` that scans its input under `guard`.

    Accepts either a string or a list of message-like dicts (`{"content": ...}`).
    Raises `GuardError` on block; substitutes redacted text on redact.
    """
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError as exc:  # pragma: no cover - env-specific
        raise ImportError(
            "langchain integration requires `pip install agentvuln[langchain]`"
        ) from exc

    g = guard or Guard()

    def _check(value: Any) -> Any:
        if isinstance(value, str):
            decision = g.scan_input(value)
            if decision.action is Action.BLOCK:
                raise GuardError("input blocked by Guard", decision.findings)
            if decision.action is Action.REDACT and decision.redacted is not None:
                return decision.redacted
            return value

        if isinstance(value, list):
            out = []
            for item in value:
                content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
                if isinstance(content, str):
                    decision = g.scan_input(content)
                    if decision.action is Action.BLOCK:
                        raise GuardError("input blocked by Guard", decision.findings)
                    if decision.action is Action.REDACT and decision.redacted is not None:
                        if isinstance(item, dict):
                            item = {**item, "content": decision.redacted}
                        else:
                            try:
                                item.content = decision.redacted
                            except AttributeError:
                                pass
                out.append(item)
            return out

        return value

    return RunnableLambda(_check)


def _callback_base() -> type:
    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError as exc:  # pragma: no cover - env-specific
        raise ImportError(
            "langchain integration requires `pip install agentvuln[langchain]`"
        ) from exc
    return BaseCallbackHandler


def make_callback_handler(guard: Guard | None = None) -> Any:
    """Construct a LangChain callback handler that scans LLM I/O."""
    base = _callback_base()
    g = guard or Guard()

    class GuardCallbackHandler(base):  # type: ignore[misc, valid-type]
        def on_llm_start(  # type: ignore[override]
            self,
            serialized: dict[str, Any],
            prompts: list[str],
            *,
            run_id: UUID,
            **kwargs: Any,
        ) -> None:
            for p in prompts:
                decision = g.scan_input(p)
                if decision.action is Action.BLOCK:
                    raise GuardError("prompt blocked by Guard", decision.findings)

        def on_llm_end(self, response: Any, **kwargs: Any) -> None:  # type: ignore[override]
            generations = getattr(response, "generations", []) or []
            for batch in generations:
                for gen in batch:
                    text = getattr(gen, "text", None)
                    if isinstance(text, str):
                        decision = g.scan_output(text)
                        if decision.action is Action.BLOCK:
                            raise GuardError("LLM output blocked by Guard", decision.findings)

    return GuardCallbackHandler()
