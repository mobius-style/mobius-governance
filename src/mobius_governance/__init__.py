# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""mobius-governance — MMV (answer-entitlement) + RCGov (context governance),
composed as a model-independent layer. No RQA on the interactive path; the ``ask``
route is a pluggable seam for opt-in async reflection.

    from mobius_governance import GovernanceComposer, OpenAICompatBackend
    composer = GovernanceComposer()
    d = composer.decide("Which is better?")           # -> route="abstain", entitled=False
    d = composer.decide("What is Python's GIL?", context=[...], task="Explain the GIL")
    if d.entitled:
        answer = OpenAICompatBackend().chat(d.prompt)  # generate on any OpenAI /v1 backend
"""
from .core import (
    GovernanceComposer, GovernanceDecision, RouteDecision,
    HeuristicRouter, InfinityRouter, build_router,
    govern_context, compose_user_text, pack_is_empty, looks_like_injection,
    ROUTE_ANSWER, ROUTE_VERIFY, ROUTE_ASK, ROUTE_ABSTAIN, ANSWERABLE_ROUTES,
)
from .backends import OpenAICompatBackend, BackendError
from .actions import (ActionDecision, ActionGate, ActionRequest, Approval,
                      FileApprovalLedger, InMemoryApprovalLedger)
from .policy import GuardEngine, PolicyError, PolicyManifest, load_policy
from .claude_hook import action_from_hook, evaluate_claude_hook

__version__ = "0.8.0"
__all__ = [
    "GovernanceComposer", "GovernanceDecision", "RouteDecision",
    "HeuristicRouter", "InfinityRouter", "build_router",
    "govern_context", "compose_user_text", "pack_is_empty", "looks_like_injection",
    "OpenAICompatBackend", "BackendError",
    "ActionDecision", "ActionGate", "ActionRequest", "Approval",
    "FileApprovalLedger", "InMemoryApprovalLedger",
    "GuardEngine", "PolicyError", "PolicyManifest", "load_policy",
    "action_from_hook", "evaluate_claude_hook",
    "ROUTE_ANSWER", "ROUTE_VERIFY", "ROUTE_ASK", "ROUTE_ABSTAIN", "ANSWERABLE_ROUTES",
    "__version__",
]
