# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""Bypass tests for the declared mediation scope.

The scope claim this file defends is deliberately narrow: *within the declared
tool set*, no effect-bearing call reaches the agent without a gate decision,
and anything the classifier does not recognise fails closed.  It is not a claim
that every effect an agent can cause is mediated -- `Bash` carries arbitrary
side effects inside one opaque string, and that limitation is asserted here as
a test rather than left as an assumption (see `test_bash_opacity_is_declared`).
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

from mobius_governance.actions import ActionGate
from mobius_governance.claude_hook import HOOK_EVENT, action_from_hook
from mobius_governance.policy import GuardEngine, PolicyError

ROOT = Path(__file__).resolve().parents[1]
HOOK_SOURCE = ROOT / "src" / "mobius_governance" / "claude_hook.py"

# The scope is declared once, here, and checked against the implementation.
DECLARED_TOOLS = {
    "Read", "Glob", "Grep", "WebSearch", "WebFetch",
    "Write", "Edit", "NotebookEdit", "Bash", "Agent", "Task",
}
NON_EFFECTFUL = {"Read", "Glob", "Grep", "WebSearch"}


def _classifier_tool_names() -> set[str]:
    """Recover the tool names the classifier actually branches on."""
    tree = ast.parse(HOOK_SOURCE.read_text(encoding="utf-8"))
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_classify"
    )
    found = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if value and value[0].isupper() and value.replace("_", "").isalnum():
                found.add(value)
    return found


class MediationCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = ActionGate(GuardEngine.from_path())

    def _decide(self, tool_name: str, tool_input: dict | None = None):
        request = action_from_hook({
            "hook_event_name": HOOK_EVENT,
            "tool_name": tool_name,
            "tool_input": tool_input if tool_input is not None else {"file_path": "/tmp/probe"},
        })
        return request, self.gate.decide(request)

    def test_declared_scope_matches_the_implementation(self) -> None:
        """The documented scope is derived from code, not maintained by hand."""
        self.assertEqual(_classifier_tool_names(), DECLARED_TOOLS)

    def test_every_declared_tool_receives_a_decision(self) -> None:
        for tool in sorted(DECLARED_TOOLS):
            with self.subTest(tool=tool):
                _, decision = self._decide(tool)
                self.assertIn(decision.decision, {"allow", "ask", "deny"})
                self.assertEqual(len(decision.action_digest), 64)

    def test_every_effectful_declared_tool_requires_approval(self) -> None:
        """No effect-bearing declared tool may reach the agent unmediated."""
        for tool in sorted(DECLARED_TOOLS - NON_EFFECTFUL):
            with self.subTest(tool=tool):
                _, decision = self._decide(tool)
                self.assertNotEqual(
                    decision.decision, "allow",
                    f"{tool} carries effects but was admitted without approval",
                )

    def test_unknown_tools_fail_closed(self) -> None:
        """Anything outside the declared set is not silently admitted."""
        for tool in (
            "mcp__vendor__transfer_funds",   # MCP server tool
            "SomeFuturePlugin",              # future first-party tool
            "bash",                          # case variation of a declared name
            "Read ",                         # whitespace variation
            "Task2",                         # near-miss of a declared name
            "R\u0435ad",                     # Cyrillic small e homoglyph of "Read"
            "\u0412ash",                     # Cyrillic Ve homoglyph of "Bash"
        ):
            with self.subTest(tool=tool):
                request, decision = self._decide(tool)
                self.assertEqual(request.operation, "unknown")
                self.assertNotEqual(decision.decision, "allow")

    def test_subagent_delegation_is_mediated(self) -> None:
        """Delegating to a child agent is itself an effect that needs a decision."""
        for tool in ("Agent", "Task"):
            with self.subTest(tool=tool):
                request, decision = self._decide(tool, {"description": "do something"})
                self.assertEqual(request.operation, "execute")
                self.assertEqual(decision.decision, "ask")

    def test_network_reaching_bash_is_marked_external(self) -> None:
        for command in ("curl https://example.com", "git push origin main", "ssh host"):
            with self.subTest(command=command):
                request, _ = self._decide("Bash", {"command": command})
                self.assertTrue(request.external)

    def test_non_pretooluse_events_are_refused(self) -> None:
        """A different hook event cannot be used to obtain a decision."""
        for event in ("PostToolUse", "Stop", "", None):
            with self.subTest(event=event):
                with self.assertRaises(PolicyError):
                    action_from_hook({
                        "hook_event_name": event,
                        "tool_name": "Write",
                        "tool_input": {"file_path": "/tmp/x"},
                    })

    def test_malformed_hook_payloads_never_yield_a_decision(self) -> None:
        for payload in (None, [], "Write", {}, {"hook_event_name": HOOK_EVENT}):
            with self.subTest(payload=repr(payload)[:24]):
                with self.assertRaises(PolicyError):
                    action_from_hook(payload)

    def test_bash_opacity_is_declared_not_assumed(self) -> None:
        """Bash is in scope as one opaque action; its interior is NOT mediated.

        This asserts the known limitation so that it cannot be quietly lost: an
        obfuscated destructive command classifies as a plain `execute`.  It is
        still gated -- it reaches `ask`, not `allow` -- but the gate cannot see
        what the shell string will actually do.  Publishing this as a passing
        test keeps the scope claim honest.
        """
        obfuscated = "echo cm0gLXJmIC8= | base64 -d | sh"
        request, decision = self._decide("Bash", {"command": obfuscated})
        self.assertEqual(request.operation, "execute")   # not classified as delete
        self.assertEqual(decision.decision, "ask")       # still mediated, never allowed


if __name__ == "__main__":
    unittest.main()
