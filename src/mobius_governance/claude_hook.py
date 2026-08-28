# SPDX-License-Identifier: AGPL-3.0-or-later
"""Claude Code PreToolUse adapter for the action gate.

The adapter never echoes tool input. It binds each decision to a digest of the
exact JSON tool input and emits Claude Code's current hookSpecificOutput shape.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .actions import ACTION_SCHEMA, ActionGate, ActionRequest
from .policy import GuardEngine, PolicyError

HOOK_EVENT = "PreToolUse"
_SENSITIVE = re.compile(
    r"(?:^|[/\\])(?:\.env(?:\.[^/\\]+)?|\.aws|\.ssh|credentials?|secrets?)(?:[/\\]|$)|"
    r"\b(?:keychain|credential store|secret store)\b",
    re.IGNORECASE,
)
_DELETE_COMMAND = re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:rm|unlink|rmdir|shred)\b", re.IGNORECASE)
_ADMIN_COMMAND = re.compile(
    r"(?:^|[;&|]\s*)(?:sudo\b|systemctl\b|useradd\b|userdel\b|chown\b|chmod\s+(?:777|[ugoa]*[+-]s))",
    re.IGNORECASE,
)


def _canonical_digest(value: Any) -> str:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"Claude hook tool_input is not canonical JSON: {exc}") from exc
    return hashlib.sha256(raw).hexdigest()


def _target(tool_name: str, tool_input: dict[str, Any]) -> str:
    for key in ("file_path", "path", "command", "url", "query", "description"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:10_000]
    return tool_name


def _classify(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, bool, bool, bool]:
    """Return operation, external, reversible, uses_credentials."""

    target = _target(tool_name, tool_input)
    sensitive = bool(_SENSITIVE.search(target))
    if tool_name in {"Read"}:
        return "read", False, True, sensitive
    if tool_name in {"Glob", "Grep"}:
        return "search", False, True, sensitive
    if tool_name == "WebSearch":
        return "search", True, True, sensitive
    if tool_name == "WebFetch":
        return "download", True, True, sensitive
    if tool_name in {"Write"}:
        return "write", False, False, sensitive
    if tool_name in {"Edit", "NotebookEdit"}:
        return "edit", False, True, sensitive
    if tool_name == "Bash":
        command = str(tool_input.get("command", ""))
        sensitive = sensitive or bool(_SENSITIVE.search(command))
        if _DELETE_COMMAND.search(command):
            return "delete", False, False, sensitive
        if _ADMIN_COMMAND.search(command):
            return "admin", False, False, sensitive
        external = bool(re.search(r"\b(?:curl|wget|ssh|scp|rsync|git\s+push|gh\s+pr|npm\s+publish)\b", command, re.IGNORECASE))
        return "execute", external, False, sensitive
    if tool_name in {"Agent", "Task"}:
        return "execute", False, True, sensitive
    return "unknown", True, False, sensitive


def action_from_hook(payload: Any) -> ActionRequest:
    if not isinstance(payload, dict):
        raise PolicyError("Claude hook input must be a JSON object")
    if payload.get("hook_event_name") != HOOK_EVENT:
        raise PolicyError("Claude hook input must be a PreToolUse event")
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_name, str) or not tool_name:
        raise PolicyError("Claude hook tool_name must be non-empty")
    if not isinstance(tool_input, dict):
        raise PolicyError("Claude hook tool_input must be an object")
    operation, external, reversible, uses_credentials = _classify(tool_name, tool_input)
    source_id = payload.get("tool_use_id") or payload.get("session_id") or "claude-pretooluse"
    if not isinstance(source_id, str) or not source_id:
        source_id = "claude-pretooluse"
    digest = _canonical_digest(tool_input)
    return ActionRequest.from_dict({
        "schema_version": ACTION_SCHEMA,
        "operation": operation,
        "tool": tool_name,
        "target": _target(tool_name, tool_input),
        "arguments": {
            "tool_input_sha256": digest,
            "field_names": sorted(str(key) for key in tool_input),
        },
        "source_ids": [source_id[:200]],
        "source_trust": ["unknown"],
        "external": external,
        "reversible": reversible,
        "uses_credentials": uses_credentials,
    })


def _hook_output(decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def evaluate_claude_hook(payload: Any, engine: GuardEngine) -> dict[str, Any]:
    request = action_from_hook(payload)
    decision = ActionGate(engine).decide(request)
    reason = (
        "MOBIUS bounded action gate: "
        + ",".join(decision.reason_codes)
        + f"; action_digest={decision.action_digest}"
    )
    return _hook_output(decision.decision, reason)


def fail_closed_hook_output(reason_code: str = "INVALID_HOOK_INPUT") -> dict[str, Any]:
    return _hook_output("deny", f"MOBIUS bounded action gate: {reason_code}")


__all__ = [
    "HOOK_EVENT", "action_from_hook", "evaluate_claude_hook",
    "fail_closed_hook_output",
]
