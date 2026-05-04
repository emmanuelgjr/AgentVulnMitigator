# AgentVulnMitigator — Viral Roadmap

> Recap of the redesign plan. Read this first at the start of each session.
> Last updated: 2026-05-03.

## The thesis
Today the project is a regex scanner + dashboard + GitHub webhook — a category with ~50 incumbents (Semgrep, Gitleaks, CodeQL). To go viral, pick **one** sharp wedge and dominate it.

**Chosen wedge: runtime guardrail SDK + attack lab.**
- Distribution loop: every protected agent is a live integration; every blocked attack is a shareable artifact.
- Why not pure scanner: no defensible moat.
- Why not pure offensive playground: no recurring usage.

## What "best in class" looks like

### 1. Runtime guardrail SDK (the product)
```python
from agentvuln import Guard
guard = Guard(policy="strict")
response = guard.protect(llm.invoke, prompt=user_input, tools=my_tools)
```
- Pre-call: scan input + retrieved context for injection / jailbreak / PII.
- Post-call: scan output for exfil, unsafe tool args, secrets.
- Tool-call interception: block SSRF, path traversal, dangerous shell **before** tool runs.
- Policy-as-code (YAML, versioned, testable).
- Modes: `block`, `redact`, `ask-human`, `log-only`.
- Three surfaces, one engine: Python SDK, HTTP sidecar, dashboard for replay/debug.

### 2. Detection that beats regex
- Layered: regex → normalization (unicode confusables, zero-width strip, base64/rot13 unwrap, homoglyph fold) → semantic classifier → policy graph.
- Indirect injection detection in RAG payloads (provenance tagging, trust downgrade for tool-fetched content).
- Per-tool arg validation (`http_get` rejects RFC1918, `read_file` chroots, `shell` denied by default).
- Memory poisoning detection on writes to vector stores.
- **Public benchmark** vs Llama Guard / NeMo / Lakera / PromptGuard on PINT, AdvBench, custom corpus. Numbers are the share asset.

### 3. The attack lab (viral surface)
- Paste system prompt + tool list → get a report of working jailbreaks with copy-pasteable transcripts.
- Replay 200+ known jailbreaks (DAN, encoded payloads, tool-call hijacks, multi-turn escalation).
- HTML report + "open issue on my repo" button.
- This is what people screenshot and post.

### 4. Distribution mechanics
- `pip install agentvuln` — 30-second install. (Today: clone the repo. That alone caps adoption near zero.)
- README leads with a 60-second attack/block GIF.
- Framework integrations: LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI Assistants, Anthropic tool-use — each is its own blog post + audience.
- Free hosted instance at a real domain (`agentvuln.com/scan`) — top of funnel.
- Docker `docker run` one-liner for the sidecar.
- Weekly "AI vuln of the week" content engine.
- MCP server: expose scanner as an MCP tool.
- GitHub Marketplace listing (not just a webhook).
- Slack/Discord blocked-attack notifier — every alert in a team channel is an ad.

### 5. Repo-level table-stakes
- **Rename** the package — `AgentVulnMitigator` is hard to type and looks like a Java class. Pick something brandable.
- `pyproject.toml` + semver + CHANGELOG, not `requirements.txt`.
- `mypy --strict`, `ruff`, 90%+ coverage, CI badges.
- `SECURITY.md`, signed releases, SBOM, disclosure address.
- Docs site (mkdocs-material).

### 6. Stop saying / delete
- "Multi-agent" — it's a guardrail today. Reclaim the word once it's true.
- Azure Sentinel claim in README — drop until something actually emits.
- Dashboard as the headline. Headline is the SDK. Dashboard is a debug tool.

## 4-week execution plan

| Week | Goal |
|------|------|
| 1 | Carve `agentvuln-core` (detector + policy engine, no FastAPI/GitHub) as a publishable Python package. Ship to PyPI under new name. Add normalization layer + 5 tool-arg validators (http, file, shell, sql, vector-write). |
| 2 | Build `Guard.protect()` SDK + LangChain & OpenAI tool-use integrations. Record 60-second attack/block GIF. Rewrite README around it. |
| 3 | Attack lab: paste prompt → jailbreak report. Hosted at a real domain. This is the launch artifact. |
| 4 | Benchmark post (vs Llama Guard / NeMo / Lakera / PromptGuard) with reproducible numbers. Launch on HN, /r/MachineLearning, LangChain Discord. The benchmark is the viral asset; the SDK is what they install after. |

The existing GitHub webhook stays, but as **one of several integrations**, not the centerpiece.

## Recommended starting point
**SDK refactor + real PyPI release.** Nothing else matters until people can `pip install` it.
