# AgentVulnMitigator
A general-purpose multi-agent AI security tool to detect and mitigate vulnerabilities in Agentic AI systems

## Features
- Detects vulnerabilities like prompt injection and data leakage.
- Mitigates risks with secure protocols.
- Web dashboard for risk visualization.
- Azure deployment with Sentinel logging.

## Setup
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8002