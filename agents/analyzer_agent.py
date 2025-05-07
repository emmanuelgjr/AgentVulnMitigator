from pydantic import BaseModel
import re

class Vulnerability(BaseModel):
    type: str
    description: str
    severity: str

class AnalyzerAgent:
    def __init__(self):
        self.vulnerabilities = []

    def analyze_input(self, user_input: str) -> list[Vulnerability]:
        """Detect vulnerabilities in user input (e.g., prompt injection)."""
        self.vulnerabilities = []

        # Example: Detect prompt injection (simplified)
        if re.search(r"(ignore|override|system)\s*(instruction|prompt)", user_input, re.IGNORECASE):
            self.vulnerabilities.append(
                Vulnerability(
                    type="Prompt Injection",
                    description="Potential attempt to override system instructions.",
                    severity="High"
                )
            )

        # Example: Detect sensitive data exposure
        if re.search(r"\d{16}", user_input):  # Simplified credit card pattern
            self.vulnerabilities.append(
                Vulnerability(
                    type="Sensitive Data Exposure",
                    description="Possible credit card number detected in input.",
                    severity="Critical"
                )
            )

        return self.vulnerabilities