from pydantic import BaseModel
from .analyzer_agent import Vulnerability  # Use relative import

class Mitigation(BaseModel):
    vulnerability_type: str
    action: str
    status: str

class MitigationAgent:
    def __init__(self):
        self.mitigations = []

    def mitigate(self, vulnerabilities: list[Vulnerability]) -> list[Mitigation]:
        """Apply mitigation strategies for detected vulnerabilities."""
        self.mitigations = []

        for vuln in vulnerabilities:
            if vuln.type == "Prompt Injection":
                self.mitigations.append(
                    Mitigation(
                        vulnerability_type=vuln.type,
                        action="Sanitize input and restrict system instruction access.",
                        status="Applied"
                    )
                )
            elif vuln.type == "Sensitive Data Exposure":
                self.mitigations.append(
                    Mitigation(
                        vulnerability_type=vuln.type,
                        action="Mask sensitive data and log for audit.",
                        status="Applied"
                    )
                )

        return self.mitigations