# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""Model-independent governance core — the two Mobius axioms, composed.

    CommitAnswer_t  => ReflectiveReady_t     # answer only when warranted   (MMV)
    InjectContext_t => ContextReady_t        # inject only what is fit to govern (RCGov)

This module is pure-stdlib except for an *optional* RCGov backend. It decides
**whether** a turn may be answered (MMV entitlement routing) and **what context**
the model is allowed to read (RCGov governance + an injection guard). It does NOT
generate — a backend does that (see ``backends``/``server``); the composer hands
back a decision + the governed prompt.

Deliberately **no RQA** (reflective questioning): that adds ~15-20 s of multi-step
reflection and is too heavy for an interactive path. The ``ask`` route is left as a
**pluggable seam** (``ask_handler``) so RQA can be attached later as an opt-in,
*asynchronous / escalation* tier without touching this core.
"""
from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .policy import GuardEngine, PolicyError

# --------------------------------------------------------------------------- #
# Route vocabulary (mirrors MMV's decision surface).
# --------------------------------------------------------------------------- #
ROUTE_ANSWER = "answer"
ROUTE_VERIFY = "verify"
ROUTE_ABSTAIN = "abstain"
ROUTE_ASK = "ask"
ANSWERABLE_ROUTES = (ROUTE_ANSWER, ROUTE_VERIFY)

RC_SAFETY = "SAFETY_INADMISSIBLE"
RC_EMPTY = "INADMISSIBLE_UNDERSPEC"
RC_MISSING_CONSTRAINTS = "MISSING_CONSTRAINTS"
RC_EMPTY_PACK = "EMPTY_CLEAN_PACK"
RC_GOVERNANCE_UNAVAILABLE = "CONTEXT_GOVERNANCE_UNAVAILABLE"

DEFAULT_ABSTAIN_MESSAGE = "I can't take this turn as posed."
DEFAULT_ASK_MESSAGE = (
    "This turn isn't answerable as stated — it's missing constraints that must be "
    "resolved first. This governance layer runs no reflective questioning on the "
    "interactive path; attach an ask_handler (async RQA) or use the full MOBIUS "
    "INFINITY stack for the clarifying-question loop: "
    "https://github.com/mobius-style/infinity"
)
DEFAULT_NO_CONTEXT_MESSAGE = (
    "Context governance admitted no segments (all retrieved context was filtered as "
    "unsafe, injection-bearing, or low-provenance) and this layer is configured to "
    "abstain rather than answer ungrounded."
)

_DEFAULT_GUARD: GuardEngine | None = None


def default_guard_engine() -> GuardEngine:
    """Load the packaged policy once; loading errors are never downgraded."""

    global _DEFAULT_GUARD
    if _DEFAULT_GUARD is None:
        _DEFAULT_GUARD = GuardEngine.from_path()
    return _DEFAULT_GUARD


def looks_like_injection(text: str) -> bool:
    """Compatibility wrapper backed by the active versioned guard policy."""

    decision = default_guard_engine().scan(text)
    return decision.decision == "drop" and any(
        hit.category != "secret" and hit.weight > 0 for hit in decision.hits
    )


# --------------------------------------------------------------------------- #
# MMV routing.
# --------------------------------------------------------------------------- #
@dataclass
class RouteDecision:
    route: str
    reason_code: str = ""
    answer_text: str = ""
    sources: list = field(default_factory=list)


class HeuristicRouter:
    """Local, model-independent answer-entitlement router (MMV decision surface,
    reduced). Reproduces MMV's route + reason_code with pure-local rules; for
    production fidelity inject a real MMV engine via ``InfinityRouter``."""

    # kill/poison narrowed to a person/animal target so benign technical uses
    # ("how to kill a background process") are not falsely gated.
    _UNSAFE = re.compile(
        r"\b(make|build|synthesi[sz]e|manufacture)\b.{0,40}\b"
        r"(bomb|explosive|nerve agent|methamphetamine|ricin)\b"
        r"|\bhow to (kill|murder|poison)\s+(a\s+|an\s+|the\s+|your\s+|my\s+)?"
        r"(person|people|someone|somebody|human|humans|him|her|them|"
        r"a man|a woman|a child|children|kids?|my \w+)\b"
        r"|\b(child sexual|csam)\b",
        re.IGNORECASE,
    )
    _EMPTY = re.compile(r"^\s*(\?+|help|thoughts\??|which is better\??|"
                        r"what do you think\??|is it good\??)\s*$", re.IGNORECASE)
    _COMPARATIVE = re.compile(
        r"\b(better|best|prefer|should i (use|pick|choose))\b", re.IGNORECASE)
    _HAS_CRITERIA = re.compile(
        r"\b(for|to|when|because|given|under|in order to|so that|with|in|on|about|"
        r"budget|latency|throughput|cost|scale|workload|use case)\b", re.IGNORECASE)

    def evaluate(self, user_input: str, session_state: Any = None) -> RouteDecision:
        text = (user_input or "").strip()
        if not text or self._EMPTY.match(text):
            return RouteDecision(ROUTE_ABSTAIN, RC_EMPTY)
        if self._UNSAFE.search(text):
            return RouteDecision(ROUTE_ABSTAIN, RC_SAFETY)
        if self._COMPARATIVE.search(text) and not self._HAS_CRITERIA.search(text):
            return RouteDecision(ROUTE_ASK, RC_MISSING_CONSTRAINTS)
        return RouteDecision(ROUTE_ANSWER, "")


class InfinityRouter:
    """Adapt a real MMV engine (ero.adapters.RoutingEngineAdapter or any object with
    ``evaluate(user_input, session_state) -> EntitlementResult``) to RouteDecision."""

    def __init__(self, entitlement_source: Any) -> None:
        self.source = entitlement_source

    def evaluate(self, user_input: str, session_state: Any = None) -> RouteDecision:
        ent = self.source.evaluate(user_input, session_state)
        return RouteDecision(
            route=(getattr(ent, "route", "") or ""),
            reason_code=(getattr(ent, "reason_code", "") or ""),
            answer_text=(getattr(ent, "answer_text", "") or ""),
            sources=list(getattr(ent, "sources", []) or []),
        )


def build_router():
    """Real INFINITY/MMV backend if INFINITY_MMV is truthy and importable (needs
    MMV_ROOT/MOBIUS_MMV + Ollama); otherwise the built-in heuristic router."""
    if os.environ.get("INFINITY_MMV", "").strip().lower() in ("1", "true", "yes", "on"):
        try:
            from ero.adapters import RoutingEngineAdapter
            from ero.wiring import build_mmv_engine
            return InfinityRouter(RoutingEngineAdapter(build_mmv_engine()))
        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"INFINITY_MMV requested but MMV backend unavailable ({exc!r}); "
                "falling back to the heuristic router.", RuntimeWarning)
    return HeuristicRouter()


# --------------------------------------------------------------------------- #
# RCGov context governance.
# --------------------------------------------------------------------------- #
def _join(context) -> str:
    if isinstance(context, list):
        return "\n\n".join(str(c) for c in context)
    return str(context)


def pack_is_empty(pack: str) -> bool:
    """True when a Clean Context Pack admitted no evidence. RCGov renders a
    "nothing admitted" pack as every section holding ``_(none)_`` while still
    echoing the task under ``## Current Task``; we check whether ANY section other
    than Current Task carries real (non-placeholder) content."""
    if not pack or not pack.strip():
        return True
    sections = re.split(r"(?m)^##\s+", pack)[1:]
    if not sections:
        return False
    for sec in sections:
        lines = sec.splitlines()
        if (lines[0] if lines else "").strip().lower().startswith("current task"):
            continue
        body = re.sub(r"_\(none\)_", "", "\n".join(lines[1:]))
        body = re.sub(r"(?m)^\s*<!--.*?-->\s*$", "", body)
        if body.strip():
            return False
    return True


def govern_context(
    context,
    task: Optional[str],
    profile: str = "Balanced",
    *,
    guard_engine: GuardEngine | None = None,
    require_rcgov: bool = False,
):
    """Govern retrieved context and return ``(clean_pack_text, meta)``.

    The packaged deterministic guard is mandatory. RCGov is an optional deeper
    classifier unless ``require_rcgov`` is true. Any mandatory-layer failure
    returns an empty pack and an explicit error, never the raw context.
    """
    try:
        engine = guard_engine or default_guard_engine()
    except PolicyError as exc:
        return "", {
            "governed": False,
            "status": "error",
            "mode": "fail_closed",
            "reason": "guard_policy_unavailable",
            "error": str(exc),
            "fail_closed": True,
            "active_rule_count": 0,
        }

    base_meta = {
        "policy": engine.manifest.to_dict(),
        "active_rule_count": engine.manifest.active_rule_count,
        "profile": profile,
        "fail_closed": False,
    }
    if not context:
        return "", {
            **base_meta,
            "governed": True,
            "status": "active",
            "mode": "builtin_guard_only",
            "reason": "empty_context",
            "injection_dropped": 0,
            "scan": None,
        }

    blobs = context if isinstance(context, list) else [context]
    try:
        kept, scan_report = engine.scan_context(blobs)
    except PolicyError as exc:
        return "", {
            **base_meta,
            "governed": False,
            "status": "error",
            "mode": "fail_closed",
            "reason": "context_scan_failed",
            "error": str(exc),
            "fail_closed": True,
        }
    dropped = scan_report["dropped_count"]

    try:
        from rcgov.service import govern_bytes
    except Exception as exc:  # noqa: BLE001 — rcgov not installed
        if require_rcgov:
            return "", {
                **base_meta,
                "governed": False,
                "status": "error",
                "mode": "fail_closed",
                "reason": "rcgov_unavailable",
                "error_type": type(exc).__name__,
                "fail_closed": True,
                "scan": scan_report,
                "injection_dropped": dropped,
            }
        return _join(kept), {
            **base_meta,
            "governed": True,
            "status": "active",
            "mode": "builtin_guard_only",
            "reason": "rcgov_optional_unavailable",
            "rcgov_status": "unavailable",
            "scan": scan_report,
            "injection_dropped": dropped,
        }
    try:
        inputs = [(f"context_{i:03d}.md",
                   f"# Retrieved context {i}\n\n{b}\n".encode("utf-8"))
                  for i, b in enumerate(kept)]
        if not inputs:
            return "", {
                **base_meta,
                "governed": True,
                "status": "active",
                "mode": "builtin_guard+rcgov",
                "rcgov_status": "not_run_no_admitted_context",
                "admitted_segment_count": 0,
                "scan": scan_report,
                "injection_dropped": dropped,
                "artifacts": [],
            }
        result = govern_bytes(inputs, task or "Answer the user's question.", profile=profile)
        return result.artifacts.get("CLEAN_CONTEXT_PACK.md", ""), {
            **base_meta,
            "governed": True,
            "status": "active",
            "mode": "builtin_guard+rcgov",
            "rcgov_status": "active",
            "admitted_segment_count": len(inputs),
            "artifact_count": len(result.artifacts),
            "scan": scan_report,
            "injection_dropped": dropped,
        }
    except Exception as exc:  # noqa: BLE001
        if require_rcgov:
            return "", {
                **base_meta,
                "governed": False,
                "status": "error",
                "mode": "fail_closed",
                "reason": "rcgov_failed",
                "error_type": type(exc).__name__,
                "fail_closed": True,
                "scan": scan_report,
                "injection_dropped": dropped,
            }
        return _join(kept), {
            **base_meta,
            "governed": True,
            "status": "degraded",
            "mode": "builtin_guard_only",
            "reason": "rcgov_optional_failed",
            "error_type": type(exc).__name__,
            "rcgov_status": "error",
            "scan": scan_report,
            "injection_dropped": dropped,
        }


def compose_user_text(text: str, safe_context: str) -> str:
    """The model-agnostic user turn: governed context + the question."""
    if safe_context and safe_context.strip():
        return (
            "Answer the question using ONLY the governed context below. "
            "If the context is insufficient, say so rather than guessing.\n\n"
            f"# Governed context\n{safe_context.strip()}\n\n"
            f"# Question\n{text.strip()}"
        )
    return text.strip()


# --------------------------------------------------------------------------- #
# The composer — decides, does not generate.
# --------------------------------------------------------------------------- #
@dataclass
class GovernanceDecision:
    route: str
    reason_code: str
    entitled: bool                 # did the turn earn a generation?
    prompt: Optional[str]          # governed user prompt to send to a backend (or None)
    message: Optional[str]         # refusal / deferral text on a non-answer route
    governed: dict
    context_empty: bool


class GovernanceComposer:
    """Compose MMV (entitlement) + RCGov (context governance) into a decision.

    Entitlement and the built-in context guard fail closed. RCGov may be optional,
    in which case its failure degrades explicitly to the still-active built-in
    guard. The ``ask`` route is an asynchronous escalation seam.
    """

    def __init__(self, router=None, *, rcgov_profile: str = "Balanced",
                 ask_handler: Optional[Callable[[str, RouteDecision], str]] = None,
                 guard_engine: GuardEngine | None = None,
                 require_rcgov: bool = False,
                 default_on_empty_pack: str = "abstain") -> None:
        if default_on_empty_pack not in {"abstain", "answer_parametric"}:
            raise ValueError("default_on_empty_pack must be abstain or answer_parametric")
        self.router = router or build_router()
        self.rcgov_profile = rcgov_profile
        self.ask_handler = ask_handler
        self.guard_engine = guard_engine or default_guard_engine()
        self.require_rcgov = require_rcgov
        self.default_on_empty_pack = default_on_empty_pack

    def decide(self, text: str, *, context=None, task: Optional[str] = None,
               rcgov_profile: Optional[str] = None,
               on_empty_pack: Optional[str] = None) -> GovernanceDecision:
        d = self.router.evaluate(text)

        if d.route not in ANSWERABLE_ROUTES:
            msg = DEFAULT_ABSTAIN_MESSAGE if d.route == ROUTE_ABSTAIN else DEFAULT_ASK_MESSAGE
            if d.route == ROUTE_ASK and self.ask_handler is not None:
                msg = self.ask_handler(text, d)   # RQA seam (async / escalation)
            return GovernanceDecision(d.route, d.reason_code, False, None, msg,
                                      {"governed": None}, False)

        empty_policy = on_empty_pack or self.default_on_empty_pack
        if empty_policy not in {"abstain", "answer_parametric"}:
            raise ValueError("on_empty_pack must be abstain or answer_parametric")
        context_supplied = bool(context)
        pack, gov = govern_context(
            context,
            task,
            rcgov_profile or self.rcgov_profile,
            guard_engine=self.guard_engine,
            require_rcgov=self.require_rcgov,
        )
        if context_supplied and gov.get("status") == "error":
            return GovernanceDecision(
                ROUTE_ABSTAIN,
                RC_GOVERNANCE_UNAVAILABLE,
                False,
                None,
                DEFAULT_NO_CONTEXT_MESSAGE,
                gov,
                True,
            )
        empty = pack_is_empty(pack) if context_supplied else False
        if context_supplied and empty and empty_policy == "abstain":
            return GovernanceDecision(ROUTE_ABSTAIN, RC_EMPTY_PACK, False, None,
                                      DEFAULT_NO_CONTEXT_MESSAGE, gov, True)
        return GovernanceDecision(d.route, d.reason_code, True,
                                  compose_user_text(text, pack), None, gov, empty)
