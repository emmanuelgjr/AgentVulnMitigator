"""High-level Guard SDK — the one thing most users will import."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from .core.analyzer import AnalyzerAgent, Vulnerability
from .core.mitigation import Mitigation, MitigationAgent

Mode = Literal["block", "redact", "log_only"]


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


class GuardError(Exception):
    """Raised by Guard.protect() when an input is blocked under `mode='block'`."""

    def __init__(self, message: str, findings: list[Vulnerability]) -> None:
        super().__init__(message)
        self.findings = findings


@dataclass
class Decision:
    action: Action
    findings: list[Vulnerability] = field(default_factory=list)
    mitigations: list[Mitigation] = field(default_factory=list)
    redacted: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action is not Action.BLOCK

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "findings": [f.model_dump() for f in self.findings],
            "mitigations": [m.model_dump() for m in self.mitigations],
            "redacted": self.redacted,
        }


_REDACTION = "[REDACTED]"


def _redact(text: str, findings: list[Vulnerability]) -> str:
    out = text
    for f in findings:
        if f.snippet:
            out = out.replace(f.snippet, _REDACTION)
    return out


@dataclass
class Guard:
    """Runtime guardrail. Wrap LLM calls or pre-screen tool args.

    Example:
        guard = Guard()
        decision = guard.scan_input(user_message)
        if not decision.allowed:
            raise RuntimeError("blocked")
    """

    policy: Literal["strict", "balanced", "permissive"] = "balanced"
    mode: Mode = "block"
    block_on_severity: tuple[str, ...] = ("Critical", "High")

    def __post_init__(self) -> None:
        self._analyzer = AnalyzerAgent()
        self._mitigator = MitigationAgent()
        if self.policy == "strict":
            self.block_on_severity = ("Critical", "High", "Medium")
        elif self.policy == "permissive":
            self.block_on_severity = ("Critical",)

    def scan_input(self, text: str) -> Decision:
        return self._evaluate(text)

    def scan_output(self, text: str) -> Decision:
        return self._evaluate(text)

    def protect(
        self,
        fn: Callable[..., Any],
        *args: Any,
        guard_inputs: tuple[str, ...] = (),
        **kwargs: Any,
    ) -> Any:
        """Run `fn(*args, **kwargs)` with input/output scanning.

        By default every string positional arg and every string kwarg is
        scanned. Pass `guard_inputs=("prompt",)` to restrict the input scan
        to specific kwargs.
        """
        if guard_inputs:
            inputs = [kwargs[k] for k in guard_inputs if isinstance(kwargs.get(k), str)]
        else:
            inputs = [a for a in args if isinstance(a, str)] + [
                v for v in kwargs.values() if isinstance(v, str)
            ]

        for value in inputs:
            decision = self.scan_input(value)
            if decision.action is Action.BLOCK:
                raise GuardError("input blocked by Guard policy", decision.findings)
            if decision.action is Action.REDACT and decision.redacted is not None:
                # Replace the offending value in-place.
                if guard_inputs:
                    for k in guard_inputs:
                        if kwargs.get(k) == value:
                            kwargs[k] = decision.redacted
                else:
                    args = tuple(
                        decision.redacted if a == value else a for a in args
                    )
                    kwargs = {
                        k: (decision.redacted if v == value else v)
                        for k, v in kwargs.items()
                    }

        result = fn(*args, **kwargs)

        if isinstance(result, str):
            out_decision = self.scan_output(result)
            if out_decision.action is Action.BLOCK:
                raise GuardError("output blocked by Guard policy", out_decision.findings)
            if out_decision.action is Action.REDACT and out_decision.redacted is not None:
                return out_decision.redacted

        return result

    def _evaluate(self, text: str) -> Decision:
        findings = self._analyzer.analyze_input(text)
        mitigations = self._mitigator.mitigate(findings)

        if not findings:
            return Decision(action=Action.ALLOW)

        triggers = [f for f in findings if f.severity in self.block_on_severity]
        if not triggers:
            return Decision(action=Action.ALLOW, findings=findings, mitigations=mitigations)

        if self.mode == "log_only":
            return Decision(action=Action.ALLOW, findings=findings, mitigations=mitigations)
        if self.mode == "redact":
            return Decision(
                action=Action.REDACT,
                findings=findings,
                mitigations=mitigations,
                redacted=_redact(text, findings),
            )
        return Decision(action=Action.BLOCK, findings=findings, mitigations=mitigations)


def scan_output(text: str) -> Decision:
    return Guard().scan_output(text)
