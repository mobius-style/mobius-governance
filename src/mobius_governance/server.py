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
    model = payload.get("model", "mobius-governance")
    gov_in = payload.get("governance") or {}
    text = _last_user(payload.get("messages", []))

    decision = composer.decide(
        text,
        context=gov_in.get("context"),
        task=gov_in.get("task"),
        rcgov_profile=gov_in.get("rcgov_profile"),
        on_empty_pack=gov_in.get("on_empty_pack", "answer_parametric"),
    )
    gov_meta = {"route": decision.route, "reason_code": decision.reason_code,
                "entitled": decision.entitled, "governed": decision.governed,
                "context_empty": decision.context_empty}
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


def create_app(composer: GovernanceComposer | None = None,
               backend: OpenAICompatBackend | None = None):
    """Build the FastAPI app (lazy import; needs the ``serve`` extra)."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    composer = composer or GovernanceComposer()
    backend = backend or OpenAICompatBackend()
    app = FastAPI(title="mobius-governance", version="0.1.0")

    @app.get("/health")
    def health():  # noqa: ANN202
        return {"status": "ok", "backend": backend.base_url, "model": backend.model}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):  # noqa: ANN202
        payload = await request.json()
        status, body, headers = handle_chat_request(payload, composer, backend.chat)
        return JSONResponse(status_code=status, content=body, headers=headers)

    return app
