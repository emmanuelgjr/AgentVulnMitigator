from fastapi import FastAPI, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agents.analyzer_agent import AnalyzerAgent
from agents.github_app import router as github_router
from agents.mitigation_agent import MitigationAgent

app = FastAPI(title="AgentVulnMitigator")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(github_router)

analyzer = AnalyzerAgent()
mitigator = MitigationAgent()

_MAX_INPUT_LEN = 10_000


@app.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "vulnerabilities": [], "mitigations": []},
    )


@app.post("/analyze")
async def analyze_input(request: Request, user_input: str = Form(..., max_length=_MAX_INPUT_LEN)):
    vulnerabilities = analyzer.analyze_input(user_input)
    mitigations = mitigator.mitigate(vulnerabilities)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "vulnerabilities": vulnerabilities,
            "mitigations": mitigations,
            "user_input": user_input,
        },
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
