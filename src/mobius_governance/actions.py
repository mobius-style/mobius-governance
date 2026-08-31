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
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .policy import GuardEngine, PolicyError


ACTION_SCHEMA = "mobius.action-request.v1"
APPROVAL_SCHEMA = "mobius.action-approval.v2"
DECISION_SCHEMA = "mobius.action-decision.v1"
_REQUEST_KEYS = {
    "schema_version", "operation", "tool", "target", "arguments",
    "source_ids", "source_trust", "external", "reversible",
    "uses_credentials",
}
_APPROVAL_KEYS = {
    "schema_version", "approval_id", "channel", "approved", "action_digest",
    "nonce", "audience", "not_after",
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
    """A single-use grant bound to one exact action instance.

    An approval names the action it authorises (``action_digest``), the single
    installation that may consume it (``audience``), the instant after which it
    is dead (``not_after``), and a ``nonce`` that a consumption ledger records
    so the same grant cannot authorise a second execution.  Binding to the
    digest alone would bind the grant to an action *class*: the same approval
    would then re-authorise every later action with identical parameters.
    """

    approval_id: str
    channel: str
    approved: bool
    action_digest: str
    nonce: str
    audience: str
    not_after: int

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
        nonce = value["nonce"]
        if not isinstance(nonce, str) or len(nonce.strip()) < 16:
            raise PolicyError("approval nonce must be a string of at least 16 characters")
        audience = value["audience"]
        if not isinstance(audience, str) or not audience.strip():
            raise PolicyError("approval audience must be a non-empty string")
        not_after = value["not_after"]
        if not isinstance(not_after, int) or isinstance(not_after, bool) or not_after <= 0:
            raise PolicyError("approval not_after must be a positive integer (unix seconds)")
        return cls(
            value["approval_id"], value["channel"], value["approved"], digest,
            nonce.strip(), audience.strip(), not_after,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": APPROVAL_SCHEMA,
            "approval_id": self.approval_id,
            "channel": self.channel,
            "approved": self.approved,
            "action_digest": self.action_digest,
            "nonce": self.nonce,
            "audience": self.audience,
            "not_after": self.not_after,
        }


def re_full_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


class InMemoryApprovalLedger:
    """Reference consumption ledger.  Suitable for tests and single-process hosts.

    A production host must replace this with independently administered,
    append-only, immutable retention: an in-process set is lost on restart, and
    a lost ledger silently restores replay.
    """

    def __init__(self) -> None:
        self._consumed: set[tuple[str, str]] = set()

    def __call__(self, approval: "Approval") -> bool:
        key = (approval.audience, approval.nonce)
        if key in self._consumed:
            return False
        self._consumed.add(key)
        return True


class FileApprovalLedger:
    """Append-only file-backed consumption ledger.

    Each consumed nonce is appended as one canonical JSON line and fsynced
    before the approval is treated as consumed, so a crash cannot lose the
    record and re-open the replay window.  This is a local-operator
    convenience, not the independently administered retention that a
    protected deployment requires.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def _seen(self, audience: str, nonce: str) -> bool:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        raise PolicyError(f"approval ledger is corrupt: {self.path}")
                    if record.get("audience") == audience and record.get("nonce") == nonce:
                        return True
        except FileNotFoundError:
            return False
        return False

    def __call__(self, approval: "Approval") -> bool:
        if self._seen(approval.audience, approval.nonce):
            return False
        record = {
            "audience": approval.audience,
            "nonce": approval.nonce,
            "approval_id": approval.approval_id,
            "action_digest": approval.action_digest,
        }
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return True


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
        approval_ledger: Callable[[Approval], bool] | None = None,
        audience: str | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(engine, GuardEngine):
            raise TypeError("ActionGate requires a GuardEngine")
        self.engine = engine
        self.approval_verifier = approval_verifier
        self.approval_ledger = approval_ledger
        self.audience = audience
        self.clock = clock or time.time

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
            # Every guard below must pass before the nonce is spent: a grant
            # rejected for any other reason stays unspent and re-presentable.
            if approval.action_digest != digest:
                reasons.append("APPROVAL_DIGEST_MISMATCH")
            elif not approval.approved:
                base = "deny"
                reasons.append("TRUSTED_USER_REJECTED")
            elif self.audience is None:
                reasons.append("APPROVAL_AUDIENCE_UNAVAILABLE")
            elif approval.audience != self.audience:
                reasons.append("APPROVAL_AUDIENCE_MISMATCH")
            elif approval.not_after <= self.clock():
                reasons.append("APPROVAL_EXPIRED")
            elif self.approval_verifier is None:
                reasons.append("APPROVAL_VERIFIER_UNAVAILABLE")
            elif not self.approval_verifier(approval, request):
                reasons.append("APPROVAL_NOT_AUTHENTICATED")
            elif self.approval_ledger is None:
                reasons.append("APPROVAL_LEDGER_UNAVAILABLE")
            elif not self.approval_ledger(approval):
                reasons.append("APPROVAL_ALREADY_CONSUMED")
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
    "ActionGate", "ActionRequest", "Approval", "FileApprovalLedger",
    "InMemoryApprovalLedger",
]
