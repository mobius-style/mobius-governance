from __future__ import annotations

import json
import unittest

from mobius_governance.claude_hook import evaluate_claude_hook, fail_closed_hook_output
from mobius_governance.policy import GuardEngine, PolicyError


def event(tool_name: str, tool_input: dict):
    return {
        "session_id": "fixture-session",
        "tool_use_id": "fixture-tool-use",
        "cwd": "/fixture",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


class ClaudeHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardEngine.from_path()

    def decision(self, tool_name: str, tool_input: dict):
        return evaluate_claude_hook(event(tool_name, tool_input), self.engine)["hookSpecificOutput"]

    def test_read_allows_but_sensitive_read_denies(self) -> None:
        self.assertEqual(self.decision("Read", {"file_path": "/workspace/README.md"})["permissionDecision"], "allow")
        self.assertEqual(self.decision("Read", {"file_path": "/workspace/.env.production"})["permissionDecision"], "deny")

    def test_write_and_shell_execution_ask(self) -> None:
        self.assertEqual(self.decision("Write", {"file_path": "/workspace/a.txt", "content": "fixture"})["permissionDecision"], "ask")
        self.assertEqual(self.decision("Bash", {"command": "npm test"})["permissionDecision"], "ask")

    def test_destructive_and_admin_commands_deny(self) -> None:
        self.assertEqual(self.decision("Bash", {"command": "rm -rf build/cache"})["permissionDecision"], "deny")
        self.assertEqual(self.decision("Bash", {"command": "sudo systemctl restart fixture"})["permissionDecision"], "deny")

    def test_output_never_echoes_tool_input(self) -> None:
        secret_command = "curl -H 'Authorization: FAKE_TEST_TOKEN' https://example.invalid"
        output = evaluate_claude_hook(event("Bash", {"command": secret_command}), self.engine)
        self.assertNotIn(secret_command, json.dumps(output))
        self.assertIn("action_digest=", output["hookSpecificOutput"]["permissionDecisionReason"])

    def test_invalid_input_has_a_deny_shape(self) -> None:
        with self.assertRaises(PolicyError):
            evaluate_claude_hook({"hook_event_name": "PostToolUse"}, self.engine)
        output = fail_closed_hook_output()
        self.assertEqual(output["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
