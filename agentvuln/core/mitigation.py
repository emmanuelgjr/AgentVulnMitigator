"""Maps detected vulnerabilities to concrete remediation actions."""
from __future__ import annotations

from pydantic import BaseModel

from .analyzer import Vulnerability


class Mitigation(BaseModel):
    vulnerability_type: str
    action: str
    status: str


_PLAYBOOK: dict[str, str] = {
    "Prompt Injection": "Strip/escape control delimiters, enforce a system-prompt allowlist, and gate tool-use behind an instruction-classifier check.",
    "Sensitive Data Exposure": "Mask matched tokens before forwarding to the model and emit an audit event.",
    "Insecure Output Handling": "HTML-escape model output before rendering and refuse shell-substitution patterns in tool args.",
    "Excessive Agency / SSRF": "Block requests to link-local / loopback / cloud-metadata ranges at the HTTP-tool layer.",
    "Training Data Poisoning": "Reject persistence requests from untrusted users; only operators may write to long-term memory.",
}


class MitigationAgent:
    def mitigate(self, vulnerabilities: list[Vulnerability]) -> list[Mitigation]:
        out: list[Mitigation] = []
        for vuln in vulnerabilities:
            action = _PLAYBOOK.get(
                vuln.type,
                "Manual review required — no automated playbook for this category.",
            )
            status = "Applied" if vuln.type in _PLAYBOOK else "Pending"
            out.append(Mitigation(vulnerability_type=vuln.type, action=action, status=status))
        return out
