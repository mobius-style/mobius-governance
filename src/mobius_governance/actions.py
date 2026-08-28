# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""Deterministic tool/action mediation for the bounded runtime MVP.

Approval is a separate typed input bound to the canonical action digest.  Text
inside an untrusted document can request an action, but it cannot manufacture
the trusted approval object used by this boundary.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .policy import GuardEngine, PolicyError


ACTION_SCHEMA = "mobius.action-request.v1"
APPROVAL_SCHEMA = "mobius.action-approval.v1"
DECISION_SCHEMA = "mobius.action-decision.v1"
_REQUEST_KEYS = {
    "schema_version", "operation", "tool", "target", "arguments",
    "source_ids", "source_trust", "external", "reversible",
    "uses_credentials",
}
_APPROVAL_KEYS = {
    "schema_version", "approval_id", "channel", "approved", "action_digest",
}
_TRUST = {"trusted", "untrusted", "unknown"}
_EFFECTFUL = {
    "write", "edit", "send", "submit", "navigate", "execute", "download",
    "upload", "delete", "purchase", "admin", "credential", "unknown",
}


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"action request is not canonical JSON: {exc}") from exc


@dataclass(frozen=True)
class ActionRequest:
    operation: str
    tool: str
    target: str
    arguments: Mapping[str, Any]
    source_ids: tuple[str, ...]
    source_trust: tuple[str, ...]
    external: bool
    reversible: bool
    uses_credentials: bool

    @classmethod
    def from_dict(cls, value: Any) -> "ActionRequest":
        if not isinstance(value, dict) or set(value) != _REQUEST_KEYS:
            raise PolicyError(f"action request must contain exactly {sorted(_REQUEST_KEYS)}")
        if value["schema_version"] != ACTION_SCHEMA:
            raise PolicyError(f"unsupported action request schema: {value['schema_version']!r}")
        for key in ("operation", "tool", "target"):
            if not isinstance(value[key], str) or not value[key].strip():
                raise PolicyError(f"action request {key} must be a non-empty string")
        if not isinstance(value["arguments"], dict):
            raise PolicyError("action request arguments must be an object")
        _canonical(value["arguments"])
        if not isinstance(value["source_ids"], list) or not all(isinstance(item, str) and item for item in value["source_ids"]):
            raise PolicyError("action request source_ids must be a string array")
        if not isinstance(value["source_trust"], list) or not all(item in _TRUST for item in value["source_trust"]):
            raise PolicyError("action request source_trust must use trusted/untrusted/unknown")
        if len(value["source_ids"]) != len(value["source_trust"]):
            raise PolicyError("source_ids and source_trust must have equal lengths")
        for key in ("external", "reversible", "uses_credentials"):
            if not isinstance(value[key], bool):
                raise PolicyError(f"action request {key} must be boolean")
        return cls(
            operation=value["operation"].strip().lower(),
            tool=value["tool"].strip(),
            target=value["target"].strip(),
            arguments=dict(value["arguments"]),
            source_ids=tuple(value["source_ids"]),
            source_trust=tuple(value["source_trust"]),
            external=value["external"],
            reversible=value["reversible"],
            uses_credentials=value["uses_credentials"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ACTION_SCHEMA,
            "operation": self.operation,
            "tool": self.tool,
            "target": self.target,
            "arguments": dict(self.arguments),
            "source_ids": list(self.source_ids),
            "source_trust": list(self.source_trust),
            "external": self.external,
            "reversible": self.reversible,
            "uses_credentials": self.uses_credentials,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class Approval:
    approval_id: str
    channel: str
    approved: bool
    action_digest: str

    @classmethod
    def from_dict(cls, value: Any) -> "Approval":
        if not isinstance(value, dict) or set(value) != _APPROVAL_KEYS:
            raise PolicyError(f"approval must contain exactly {sorted(_APPROVAL_KEYS)}")
        if value["schema_version"] != APPROVAL_SCHEMA:
            raise PolicyError(f"unsupported approval schema: {value['schema_version']!r}")
        if not isinstance(value["approval_id"], str) or not value["approval_id"].strip():
            raise PolicyError("approval_id must be a non-empty string")
        if value["channel"] != "trusted_user":
            raise PolicyError("approval channel must be trusted_user")
        if not isinstance(value["approved"], bool):
            raise PolicyError("approval approved must be boolean")
        digest = value["action_digest"]
        if not isinstance(digest, str) or not re_full_hex(digest):
            raise PolicyError("approval action_digest must be 64 lowercase hexadecimal characters")
        return cls(value["approval_id"], value["channel"], value["approved"], digest)


def re_full_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


@dataclass(frozen=True)
class ActionDecision:
    decision: str
    reason_codes: tuple[str, ...]
    action_digest: str
    approval_required: bool
    policy: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": DECISION_SCHEMA,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "action_digest": self.action_digest,
            "approval_required": self.approval_required,
            "policy": dict(self.policy),
        }


class ActionGate:
    """Mediates proposed effects using policy plus exact-action approval binding."""

    def __init__(
        self,
        engine: GuardEngine,
        *,
        approval_verifier: Callable[[Approval, ActionRequest], bool] | None = None,
    ) -> None:
        if not isinstance(engine, GuardEngine):
            raise TypeError("ActionGate requires a GuardEngine")
        self.engine = engine
        self.approval_verifier = approval_verifier

    def decide(self, request: ActionRequest, approval: Approval | None = None) -> ActionDecision:
        rules = self.engine.policy.action_rules
        operation = request.operation if request.operation in rules else "unknown"
        base = rules.get(operation, rules["unknown"])
        reasons = [f"POLICY_{base.upper()}"]

        if request.uses_credentials:
            base = "deny"
            reasons.append("CREDENTIAL_USE_DENIED")
        if not request.reversible and operation in {"delete", "purchase", "admin"}:
            base = "deny"
            reasons.append("IRREVERSIBLE_HIGH_IMPACT_DENIED")
        untrusted = any(item != "trusted" for item in request.source_trust)
        if untrusted and operation in _EFFECTFUL and base == "allow":
            base = "ask"
            reasons.append("UNTRUSTED_SOURCE_CANNOT_AUTHORIZE_EFFECT")
        if request.external and operation in _EFFECTFUL and base == "allow":
            base = "ask"
            reasons.append("EXTERNAL_EFFECT_REQUIRES_APPROVAL")

        digest = request.digest
        if base == "ask" and approval is not None:
            if approval.action_digest != digest:
                reasons.append("APPROVAL_DIGEST_MISMATCH")
            elif not approval.approved:
                base = "deny"
                reasons.append("TRUSTED_USER_REJECTED")
            elif self.approval_verifier is None:
                reasons.append("APPROVAL_VERIFIER_UNAVAILABLE")
            elif not self.approval_verifier(approval, request):
                reasons.append("APPROVAL_NOT_AUTHENTICATED")
            else:
                base = "allow"
                reasons.append("EXACT_ACTION_APPROVED")

        return ActionDecision(
            decision=base,
            reason_codes=tuple(dict.fromkeys(reasons)),
            action_digest=digest,
            approval_required=base == "ask",
            policy=self.engine.manifest.to_dict(),
        )


__all__ = [
    "ACTION_SCHEMA", "APPROVAL_SCHEMA", "DECISION_SCHEMA", "ActionDecision",
    "ActionGate", "ActionRequest", "Approval",
]
