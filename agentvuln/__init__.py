"""agentvuln — runtime guardrail SDK for agentic AI systems.

Public surface:

    from agentvuln import Guard, Vulnerability, Mitigation
    from agentvuln import scan_input, scan_output

A `Guard` is the recommended entry point. It composes the detector,
the normalizer, the policy engine, and the per-tool argument validators.
"""
from __future__ import annotations

from .core.analyzer import AnalyzerAgent, Vulnerability, scan_input
from .core.mitigation import Mitigation, MitigationAgent
from .core.normalize import normalize
from .guard import Decision, Guard, GuardError, scan_output

__all__ = [
    "AnalyzerAgent",
    "Decision",
    "Guard",
    "GuardError",
    "Mitigation",
    "MitigationAgent",
    "Vulnerability",
    "normalize",
    "scan_input",
    "scan_output",
]

__version__ = "0.1.0"
