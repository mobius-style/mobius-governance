# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""OpenAI-compatible governance proxy.

Point any OpenAI client's ``base_url`` here and every turn is routed by MMV
(answer-entitlement) and its context governed by RCGov before the backend model
sees it — governance surfaced without breaking compatibility, via a non-standard
``governance`` object on the JSON body and ``x-governance-*`` response headers.

The request/response mapping is a pure function (``handle_chat_request``) so it is
**network-free testable**; FastAPI/uvicorn are imported lazily (only for ``serve``).
"""
from __future__ import annotations

from typing import Any, Callable

from .core import (GovernanceComposer, ROUTE_ABSTAIN, ROUTE_ASK,
                   DEFAULT_ABSTAIN_MESSAGE)
from .backends import OpenAICompatBackend, BackendError
from .actions import ActionGate, ActionRequest
from .policy import GuardEngine, PolicyError

_FIXED_TS = 0  # created timestamp; wall-clock is irrelevant to callers and unbounded here.


def _completion(model: str, text: str, *, finish_reason: str, governance: dict) -> dict:
    return {
        "id": "govchatcmpl", "object": "chat.completion", "created": _FIXED_TS,
        "model": model,
        "choices": [{"index": 0, "finish_reason": finish_reason,
                     "message": {"role": "assistant", "content": text}}],
        "governance": governance,   # non-standard, additive
    }


def _last_user(messages: list) -> str:
    for m in reversed(messages or []):
        if not isinstance(m, dict):
            continue
        if m.get("role") == "user":
            c = m.get("content", "")
            if isinstance(c, list):  # multimodal content array -> concat text parts
                return "".join(p.get("text", "") for p in c if isinstance(p, dict))
            return c
    return ""


def handle_chat_request(payload: dict, composer: GovernanceComposer,
                        backend_chat: Callable[..., str]) -> tuple[int, dict, dict]:
    """Map an OpenAI chat-completions request to a governed response.

    Returns ``(http_status, body, headers)``. ``backend_chat(prompt, **params) -> str``
    is injected, so this is testable with no network. Governance decides; the
    backend only runs on the answer branch.
    """
    if not isinstance(payload, dict):
        return 400, {"error": {"message": "request body must be a JSON object",
                               "type": "invalid_request_error",
                               "code": "invalid_request"}}, {}
    model = payload.get("model", "mobius-governance")
    gov_in = payload.get("governance") or {}
    if not isinstance(gov_in, dict):
        return 400, {"error": {"message": "governance must be a JSON object",
                               "type": "invalid_request_error",
                               "code": "invalid_governance"}}, {}
    text = _last_user(payload.get("messages", []))

    decision = composer.decide(
        text,
        context=gov_in.get("context"),
        task=gov_in.get("task"),
    )
    ignored_overrides = sorted(
        key for key in ("rcgov_profile", "on_empty_pack") if key in gov_in
    )
    gov_meta = {"route": decision.route, "reason_code": decision.reason_code,
                "entitled": decision.entitled, "governed": decision.governed,
                "context_empty": decision.context_empty,
                "request_overrides_ignored": ignored_overrides}
    headers = {"x-governance-route": decision.route,
               "x-governance-entitled": str(decision.entitled).lower(),
               "x-governance-reason": decision.reason_code or "-"}

    if not decision.entitled:
        # abstain -> content_filter; ask -> stop (it's a legitimate clarifying turn)
        fr = "content_filter" if decision.route == ROUTE_ABSTAIN else "stop"
        return 200, _completion(model, decision.message or DEFAULT_ABSTAIN_MESSAGE,
                                finish_reason=fr, governance=gov_meta), headers

    gen_params = {k: v for k, v in payload.items()
                  if k in ("temperature", "top_p", "max_tokens", "max_new_tokens",
                           "stop", "seed", "presence_penalty", "frequency_penalty")}
    try:
        text_out = backend_chat(decision.prompt, **gen_params)
    except BackendError as e:
        return 503, {"error": {"message": str(e), "type": "backend_unavailable",
                               "code": "backend_unavailable"}}, headers
    return 200, _completion(model, text_out, finish_reason="stop",
                            governance=gov_meta), headers


def handle_scan_request(payload: dict, engine: GuardEngine) -> tuple[int, dict]:
    """Scan typed context segments without returning their raw contents."""

    if not isinstance(payload, dict) or set(payload) != {"schema_version", "segments"}:
        return 400, {"error": "scan request needs exactly schema_version and segments"}
    if payload["schema_version"] != "mobius.context-scan-request.v1":
        return 400, {"error": "unsupported scan request schema"}
    if not isinstance(payload["segments"], list):
        return 400, {"error": "segments must be an array"}
    try:
        _, report = engine.scan_context(payload["segments"])
    except PolicyError as exc:
        return 400, {"error": str(exc)}
    return 200, report


def handle_action_request(payload: dict, gate: ActionGate) -> tuple[int, dict]:
    """Decide a proposed effect without trusting caller-supplied approvals."""

    if not isinstance(payload, dict) or set(payload) != {"request"}:
        return 400, {"error": "action body needs exactly request; approvals require a trusted host verifier"}
    try:
        request = ActionRequest.from_dict(payload["request"])
        decision = gate.decide(request)
    except (PolicyError, TypeError) as exc:
        return 400, {"error": str(exc)}
    return 200, decision.to_dict()


def create_app(composer: GovernanceComposer | None = None,
               backend: OpenAICompatBackend | None = None):
    """Build the FastAPI app (lazy import; needs the ``serve`` extra)."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    composer = composer or GovernanceComposer()
    backend = backend or OpenAICompatBackend()
    engine = composer.guard_engine
    gate = ActionGate(engine)
    app = FastAPI(title="mobius-governance", version="0.7.0")

    @app.get("/health")
    def health():  # noqa: ANN202
        try:
            calibration = engine.self_check()
            status = "ok" if calibration["status"] == "PASS" else "error"
        except PolicyError as exc:
            calibration = {"status": "ERROR", "error": str(exc)}
            status = "error"
        body = {
            "status": status,
            "backend": backend.base_url,
            "model": backend.model,
            "policy": engine.manifest.to_dict(),
            "detector": engine.detector,
            "calibration": calibration,
        }
        return JSONResponse(status_code=200 if status == "ok" else 503, content=body)

    @app.post("/v1/governance/scan")
    async def context_scan(request: Request):  # noqa: ANN202
        payload = await request.json()
        status, body = handle_scan_request(payload, engine)
        return JSONResponse(status_code=status, content=body)

    @app.post("/v1/governance/actions/decide")
    async def action_decision(request: Request):  # noqa: ANN202
        payload = await request.json()
        status, body = handle_action_request(payload, gate)
        return JSONResponse(status_code=status, content=body)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):  # noqa: ANN202
        payload = await request.json()
        status, body, headers = handle_chat_request(payload, composer, backend.chat)
        return JSONResponse(status_code=status, content=body, headers=headers)

    return app
