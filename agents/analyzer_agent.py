"""Compatibility shim — use `from agentvuln import AnalyzerAgent, Vulnerability` instead."""
from agentvuln.core.analyzer import AnalyzerAgent, Vulnerability

__all__ = ["AnalyzerAgent", "Vulnerability"]
