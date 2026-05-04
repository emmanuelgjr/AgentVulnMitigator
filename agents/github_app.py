"""GitHub App / webhook integration.

Receives signed webhook events, runs the analyzer over the relevant content,
and (when credentials are configured) reports findings back to GitHub as a
check run on the PR head SHA or as a comment on the issue.

Credentials are optional: if no app credentials are configured the handler
still verifies signatures and returns the findings in the response body, which
makes it easy to test locally with `curl` or a webhook proxy.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status

from .analyzer_agent import AnalyzerAgent, Vulnerability
from .mitigation_agent import MitigationAgent

log = logging.getLogger(__name__)

router = APIRouter(prefix="/github", tags=["github"])

_analyzer = AnalyzerAgent()
_mitigator = MitigationAgent()

GITHUB_API = "https://api.github.com"
_MAX_BODY_BYTES = 1_000_000  # 1 MB cap on webhook payloads


def _settings() -> dict[str, str | None]:
    return {
        "secret": os.getenv("GITHUB_WEBHOOK_SECRET"),
        "app_id": os.getenv("GITHUB_APP_ID"),
        "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY"),
    }


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _app_jwt(app_id: str, private_key_pem: str) -> str:
    """Mint a short-lived JWT for the GitHub App.

    Imported lazily so the app boots without `PyJWT` installed when the
    webhook is only being used for signature-verified scanning.
    """
    import jwt  # type: ignore[import-not-found]

    now = int(time.time())
    return jwt.encode(
        {"iat": now - 30, "exp": now + 9 * 60, "iss": app_id},
        private_key_pem,
        algorithm="RS256",
    )


async def _installation_token(client: httpx.AsyncClient, installation_id: int) -> str:
    cfg = _settings()
    if not (cfg["app_id"] and cfg["private_key"]):
        raise RuntimeError("GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set to call the GitHub API.")
    jwt_token = _app_jwt(cfg["app_id"], cfg["private_key"])
    resp = await client.post(
        f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
        headers={"Authorization": f"Bearer {jwt_token}", "Accept": "application/vnd.github+json"},
    )
    resp.raise_for_status()
    return resp.json()["token"]


def _scan_text(text: str) -> list[Vulnerability]:
    return _analyzer.analyze_input(text or "")


def _scan_diff(diff_text: str) -> list[Vulnerability]:
    """Run the analyzer on added lines of a unified diff."""
    added: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    if not added:
        return []
    return _scan_text("\n".join(added))


def _findings_markdown(findings: list[Vulnerability]) -> str:
    if not findings:
        return "**AgentVulnMitigator:** no vulnerabilities detected."
    lines = ["**AgentVulnMitigator findings**", "", "| Severity | Type | Description |", "|---|---|---|"]
    for v in findings:
        lines.append(f"| {v.severity} | {v.type} | {v.description} |")
    return "\n".join(lines)


async def _handle_pull_request(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("action") not in {"opened", "synchronize", "reopened"}:
        return {"skipped": True, "reason": f"action={payload.get('action')}"}

    pr = payload["pull_request"]
    diff_url = pr["diff_url"]
    head_sha = pr["head"]["sha"]
    repo_full = payload["repository"]["full_name"]
    installation_id = (payload.get("installation") or {}).get("id")

    async with httpx.AsyncClient(timeout=15) as client:
        diff_resp = await client.get(diff_url, headers={"Accept": "application/vnd.github.v3.diff"})
        diff_resp.raise_for_status()
        findings = _scan_diff(diff_resp.text)

        reported = False
        if installation_id and _settings()["app_id"]:
            token = await _installation_token(client, installation_id)
            conclusion = "neutral" if not findings else (
                "failure" if any(v.severity in {"Critical", "High"} for v in findings) else "neutral"
            )
            check = await client.post(
                f"{GITHUB_API}/repos/{repo_full}/check-runs",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                json={
                    "name": "AgentVulnMitigator",
                    "head_sha": head_sha,
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": {
                        "title": f"{len(findings)} finding(s)",
                        "summary": _findings_markdown(findings),
                    },
                },
            )
            reported = check.is_success

    return {
        "event": "pull_request",
        "repo": repo_full,
        "head_sha": head_sha,
        "findings": [v.model_dump() for v in findings],
        "mitigations": [m.model_dump() for m in _mitigator.mitigate(findings)],
        "reported_to_github": reported,
    }


async def _handle_issue_comment(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("action") != "created":
        return {"skipped": True, "reason": f"action={payload.get('action')}"}

    comment = payload["comment"]
    if (comment.get("user") or {}).get("type") == "Bot":
        return {"skipped": True, "reason": "bot comment"}

    findings = _scan_text(comment.get("body", ""))
    repo_full = payload["repository"]["full_name"]
    issue_number = payload["issue"]["number"]
    installation_id = (payload.get("installation") or {}).get("id")

    reported = False
    if findings and installation_id and _settings()["app_id"]:
        async with httpx.AsyncClient(timeout=15) as client:
            token = await _installation_token(client, installation_id)
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo_full}/issues/{issue_number}/comments",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                json={"body": _findings_markdown(findings)},
            )
            reported = resp.is_success

    return {
        "event": "issue_comment",
        "repo": repo_full,
        "issue": issue_number,
        "findings": [v.model_dump() for v in findings],
        "reported_to_github": reported,
    }


@router.post("/webhook")
async def github_webhook(request: Request) -> dict[str, Any]:
    secret = _settings()["secret"]
    if not secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GITHUB_WEBHOOK_SECRET not configured")

    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")

    if not verify_signature(secret, raw, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")

    event = request.headers.get("X-GitHub-Event", "")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid JSON body")

    if event == "ping":
        return {"event": "ping", "ok": True}
    if event == "pull_request":
        return await _handle_pull_request(payload)
    if event == "issue_comment":
        return await _handle_issue_comment(payload)

    return {"event": event, "skipped": True, "reason": "unhandled event type"}
