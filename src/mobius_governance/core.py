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

# --------------------------------------------------------------------------- #
# Prompt-injection guard (defense-in-depth over RCGov).
#
# RCGov's built-in injection detector is seed-based (two literal substrings) and
# leaks the common imperative-override phrasings ("ignore ALL previous
# instructions", "you are now DAN", "SYSTEM: override safety"). This guard drops
# obvious override / role-hijack / prompt-exfiltration context BEFORE governance.
# Heuristic (recall 100% / FP 0% on eval/injection_corpus.py), NOT a complete
# defense; secret/low-provenance filtering remains RCGov's job.
# --------------------------------------------------------------------------- #
_INJECTION_GUARD = re.compile(
    r"(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
    r"\b(?:instruction|instructions|rule|rules|prompt|context|above|previous|prior|"
    r"everything|all)\b"
    r"|\b(?:reveal|print|show|expose|leak|repeat|output)\b[^.\n]{0,30}?"
    r"\b(?:system prompt|your prompt|your instructions|the prompt|secret|secrets|"
    r"api[ _-]?key)\b"
    r"|\byou are now\b|\bpretend (?:to be|you are)\b"
    r"|\bdeveloper mode\b|\bjailbreak\b|\bDAN\b"
    r"|^\s*system\s*:|\bnew instructions?\s*:|\boverride (?:safety|the rules|all)\b",
    re.IGNORECASE | re.MULTILINE,
)


def looks_like_injection(text: str) -> bool:
    """Heuristic imperative-override / role-hijack detector (see _INJECTION_GUARD)."""
    return bool(_INJECTION_GUARD.search(text or ""))


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
    for sec in re.split(r"(?m)^##\s+", pack)[1:]:
        lines = sec.splitlines()
        if (lines[0] if lines else "").strip().lower().startswith("current task"):
            continue
        body = re.sub(r"_\(none\)_", "", "\n".join(lines[1:]))
        body = re.sub(r"(?m)^\s*<!--.*?-->\s*$", "", body)
        if body.strip():
            return False
    return True


def govern_context(context, task: Optional[str], profile: str = "Balanced"):
    """Govern retrieved context and return ``(clean_pack_text, meta)``.

    Fail-open: if RCGov is missing or errors we answer WITHOUT governance and flag
    ``governed=False`` (the injection pre-filter still holds). The injection guard
    runs BEFORE RCGov because RCGov's own detector leaks common phrasings. Bare
    prose is wrapped under a heading so RCGov segments it as placeable *evidence*
    (un-headed prose is classed as un-injectable "preamble" and withheld)."""
    if not context:
        return "", {"governed": False, "reason": "empty_context", "injection_dropped": 0}

    blobs = [str(b) for b in (context if isinstance(context, list) else [context])]
    kept, dropped = [], 0
    for b in blobs:
        if looks_like_injection(b):
            dropped += 1
        else:
            kept.append(b)

    try:
        from rcgov.service import govern_bytes
    except Exception as exc:  # noqa: BLE001 — rcgov not installed
        warnings.warn(
            f"rcgov unavailable ({exc!r}); answering WITHOUT context governance. "
            "Install: pip install 'rcgov @ git+https://github.com/mobius-style/rcgov.git'",
            RuntimeWarning)
        return _join(kept), {"governed": False, "reason": "rcgov_unavailable",
                             "injection_dropped": dropped}
    try:
        inputs = [(f"context_{i:03d}.md",
                   f"# Retrieved context {i}\n\n{b}\n".encode("utf-8"))
                  for i, b in enumerate(kept)]
        if not inputs:
            return "", {"governed": True, "profile": profile,
                        "summary": "0 segments (all context dropped by injection guard)",
                        "injection_dropped": dropped, "artifacts": []}
        result = govern_bytes(inputs, task or "Answer the user's question.", profile=profile)
        return result.artifacts.get("CLEAN_CONTEXT_PACK.md", ""), {
            "governed": True, "profile": profile, "summary": result.summary,
            "injection_dropped": dropped, "artifacts": sorted(result.artifacts.keys())}
    except Exception as exc:  # noqa: BLE001
        warnings.warn(f"rcgov.govern_bytes failed ({exc!r}); answering WITHOUT governance.",
                      RuntimeWarning)
        return _join(kept), {"governed": False, "reason": f"error:{exc!r}",
                             "injection_dropped": dropped}


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

    Entitlement fails CLOSED (abstain/ask never reach the model); governance fails
    OPEN (RCGov missing/error -> answer on raw context, flagged). The ``ask`` route
    is the RQA seam: pass ``ask_handler(text, decision) -> str`` to escalate (e.g.
    async reflective questioning); by default an ``ask`` defers with a message.
    """

    def __init__(self, router=None, *, rcgov_profile: str = "Balanced",
                 ask_handler: Optional[Callable[[str, RouteDecision], str]] = None) -> None:
        self.router = router or build_router()
        self.rcgov_profile = rcgov_profile
        self.ask_handler = ask_handler

    def decide(self, text: str, *, context=None, task: Optional[str] = None,
               rcgov_profile: Optional[str] = None,
               on_empty_pack: str = "answer_parametric") -> GovernanceDecision:
        d = self.router.evaluate(text)

        if d.route not in ANSWERABLE_ROUTES:
            msg = DEFAULT_ABSTAIN_MESSAGE if d.route == ROUTE_ABSTAIN else DEFAULT_ASK_MESSAGE
            if d.route == ROUTE_ASK and self.ask_handler is not None:
                msg = self.ask_handler(text, d)   # RQA seam (async / escalation)
            return GovernanceDecision(d.route, d.reason_code, False, None, msg,
                                      {"governed": None}, False)

        pack, gov = govern_context(context, task, rcgov_profile or self.rcgov_profile)
        empty = pack_is_empty(pack) if gov.get("governed") else not bool(context)
        if empty and on_empty_pack == "abstain":
            return GovernanceDecision(ROUTE_ABSTAIN, RC_EMPTY_PACK, False, None,
                                      DEFAULT_NO_CONTEXT_MESSAGE, gov, True)
        return GovernanceDecision(d.route, d.reason_code, True,
                                  compose_user_text(text, pack), None, gov, empty)
