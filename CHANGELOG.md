# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-03

### Added
- New `agentvuln` package — runtime guardrail SDK for agentic AI systems.
- `Guard` SDK with `scan_input`, `scan_output`, and `protect(fn, ...)`.
  Supports `block` / `redact` / `log_only` modes and `strict` / `balanced` /
  `permissive` policies.
- OWASP-LLM-aligned detector: Prompt Injection (direct + indirect + jailbreak
  personas), Sensitive Data Exposure (cards + OpenAI/AWS/GitHub/Slack tokens),
  Insecure Output Handling (XSS + shell), Excessive Agency / SSRF, Training
  Data Poisoning.
- Input normalization layer: zero-width strip, Unicode confusable fold,
  base64 / hex / rot13 unwrap, spaced-letter collapse. Findings carry
  `via_normalization=True` when the bypass was caught only after normalization.
- Per-tool argument validators in `agentvuln.validators`:
  `validate_http_url` (RFC1918 / metadata / DNS rebinding),
  `validate_file_path` (chroot), `validate_shell_command` (deny-by-default),
  `validate_sql_query` (multi-statement / DDL / write-without-WHERE),
  `validate_vector_write` (memory-poisoning guard).
- Framework integrations:
  `agentvuln.integrations.openai.GuardedOpenAI` (drop-in proxy around the
  OpenAI client), `agentvuln.integrations.langchain.guard_runnable` and
  `make_callback_handler` (LCEL Runnable + `BaseCallbackHandler`).
- `examples/demo.py` plus `examples/demo.tape` for VHS-based GIF recording.
- FastAPI dashboard + signed GitHub webhook (`/github/webhook`, `/healthz`,
  `/analyze`) under the `[server]` extra. Webhook verifies HMAC signatures
  and posts findings as a Check Run on PR diffs or as a comment on issues.
- CI matrix: lint (`ruff`) + tests (`pytest`) on Python 3.10 / 3.11 / 3.12,
  plus a `python -m build` job that uploads wheel + sdist artifacts.
- `pyproject.toml` (Hatch backend) replacing `setup.py`; package now
  installable as `pip install -e .`.
- `ROADMAP.md`, `docs/RELEASING.md`, `examples/README.md`.

### Changed
- README rewritten around the SDK as the headline; FastAPI app + GitHub
  webhook reframed as one of several integrations rather than the centerpiece.
- `agents/` retained as compatibility shims that re-export the new
  `agentvuln.core` types — existing imports keep working.

### Fixed
- `agents/_init_.py` and `tests/_init_.py` had single-underscore names and
  weren't recognized as package markers; renamed to `__init__.py`.
- README had duplicated **Features** / **Setup** sections and an unclosed
  fenced code block.
- The previously listed `<script>` "attack" payload in `tests/red_team.py`
  is now actually flagged by the detector.
- `Vulnerability.dict()` / `Mitigation.dict()` (deprecated in Pydantic v2)
  replaced with `.model_dump()`.
- `requirements.txt` no longer pins `rigging` or `azure-*` packages that
  nothing imports.

### Security
- `/analyze` endpoint now caps user input at 10 000 characters.
- `/github/webhook` caps request body at 1 MB and rejects requests with a
  missing or invalid `X-Hub-Signature-256`.
