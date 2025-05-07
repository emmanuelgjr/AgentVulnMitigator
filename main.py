from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from agents.analyzer_agent import AnalyzerAgent
from agents.mitigation_agent import MitigationAgent

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

analyzer = AnalyzerAgent()
mitigator = MitigationAgent()

@app.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "vulnerabilities": [], "mitigations": []})

@app.post("/analyze")
async def analyze_input(request: Request, user_input: str = Form(...)):
    vulnerabilities = analyzer.analyze_input(user_input)
    mitigations = mitigator.mitigate(vulnerabilities)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "vulnerabilities": vulnerabilities, "mitigations": mitigations, "user_input": user_input}
    )