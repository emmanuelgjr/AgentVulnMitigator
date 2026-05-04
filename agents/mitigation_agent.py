"""Compatibility shim — use `from agentvuln import Mitigation, MitigationAgent` instead."""
from agentvuln.core.mitigation import Mitigation, MitigationAgent

__all__ = ["Mitigation", "MitigationAgent"]
