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

from .actions import ACTION_SCHEMA, ActionGate, ActionRequest, _compound_tokens
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


# Fields whose value is executed rather than stored, searched, or displayed.
_EXECUTABLE_FIELDS = frozenset({"command", "cmd", "script", "argv", "args", "shell"})


def _target(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Pick the field that names what the call acts on.

    ``command`` is checked first: when a shell command is present it is the
    effect, and letting a co-occurring ``file_path`` win would hide it from the
    compound scan entirely.  The value is not truncated here -- truncating it
    let a caller push chaining operators past the cut-off and silence the
    warning -- so truncation happens only at render time, where the full value
    is still hashed.
    """

    for key in ("command", "file_path", "path", "url", "query", "description"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return tool_name


def _strings(value: Any) -> list[str]:
    """Every string anywhere in a value, at any nesting depth."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items()
                for s in _strings(key) + _strings(item)]
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _strings(item)]
    return []


def _classify(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, bool, bool, bool]:
    """Return operation, external, reversible, uses_credentials."""

    target = _target(tool_name, tool_input)
    # Scan every string in the input, not only the one field chosen as target:
    # preferring `command` for the compound scan would otherwise hide a
    # credential path sitting in a co-occurring `file_path`.
    sensitive = any(
        bool(_SENSITIVE.search(item))
        for item in _strings(tool_input)
    ) or bool(_SENSITIVE.search(target))
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
            # Chaining markers from the fields that carry a command, including
            # an argv list or a nested mapping.  Scanning the whole input would
            # be worse than scanning too little: file content, edit
            # replacements, and search patterns legitimately contain newlines
            # and pipes, so the warning would fire on most ordinary calls and
            # be trained away -- the same failure the bare "&" exclusion exists
            # to avoid.  Only the markers travel, never the input.
            "chaining_markers": sorted(_compound_tokens(
                {key: value for key, value in tool_input.items()
                 if key in _EXECUTABLE_FIELDS}
            )),
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
    # The reason string is the only surface a human sees on this path, so the
    # rendering of what they are approving has to travel with the verdict.
    # Reason codes and a digest tell an approver that a decision happened; they
    # do not tell them what they would be approving.
    reason = (
        "MOBIUS bounded action gate: "
        + ",".join(decision.reason_codes)
        + f"; action_digest={decision.action_digest}\n"
        + request.summary(redact_values=True)
    )
    return _hook_output(decision.decision, reason)


def fail_closed_hook_output(reason_code: str = "INVALID_HOOK_INPUT") -> dict[str, Any]:
    return _hook_output("deny", f"MOBIUS bounded action gate: {reason_code}")


__all__ = [
    "HOOK_EVENT", "action_from_hook", "evaluate_claude_hook",
    "fail_closed_hook_output",
]
