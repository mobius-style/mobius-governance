from __future__ import annotations

import math
import unittest

from mobius_governance.actions import APPROVAL_SCHEMA, ACTION_SCHEMA, ActionGate, ActionRequest, Approval
from mobius_governance.policy import GuardEngine, PolicyError


def request_dict(operation: str = "write", **overrides):
    value = {
        "schema_version": ACTION_SCHEMA,
        "operation": operation,
        "tool": "fixture",
        "target": "fixture-target",
        "arguments": {"value": 1},
        "source_ids": ["fixture-source"],
        "source_trust": ["untrusted"],
        "external": False,
        "reversible": True,
        "uses_credentials": False,
    }
    value.update(overrides)
    return value


class ActionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = ActionGate(GuardEngine.from_path())

    def test_read_is_allowed_but_write_asks(self) -> None:
        self.assertEqual(self.gate.decide(ActionRequest.from_dict(request_dict("read"))).decision, "allow")
        self.assertEqual(self.gate.decide(ActionRequest.from_dict(request_dict("write"))).decision, "ask")

    def test_unknown_operation_never_silently_allows(self) -> None:
        decision = self.gate.decide(ActionRequest.from_dict(request_dict("launch_rocket")))
        self.assertEqual(decision.decision, "ask")
        self.assertTrue(decision.approval_required)

    def test_exact_digest_approval_allows_ask_action(self) -> None:
        request = ActionRequest.from_dict(request_dict("write"))
        approval = Approval.from_dict({
            "schema_version": APPROVAL_SCHEMA,
            "approval_id": "approval-1",
            "channel": "trusted_user",
            "approved": True,
            "action_digest": request.digest,
        })
        decision = ActionGate(
            GuardEngine.from_path(), approval_verifier=lambda supplied, action: True
        ).decide(request, approval)
        self.assertEqual(decision.decision, "allow")
        self.assertIn("EXACT_ACTION_APPROVED", decision.reason_codes)

    def test_unverified_self_asserted_approval_never_allows(self) -> None:
        request = ActionRequest.from_dict(request_dict("write"))
        approval = Approval.from_dict({
            "schema_version": APPROVAL_SCHEMA,
            "approval_id": "self-asserted",
            "channel": "trusted_user",
            "approved": True,
            "action_digest": request.digest,
        })
        decision = self.gate.decide(request, approval)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_VERIFIER_UNAVAILABLE", decision.reason_codes)

    def test_approval_cannot_be_replayed_for_changed_action(self) -> None:
        first = ActionRequest.from_dict(request_dict("write", target="first"))
        second = ActionRequest.from_dict(request_dict("write", target="second"))
        approval = Approval.from_dict({
            "schema_version": APPROVAL_SCHEMA,
            "approval_id": "approval-1",
            "channel": "trusted_user",
            "approved": True,
            "action_digest": first.digest,
        })
        decision = self.gate.decide(second, approval)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_DIGEST_MISMATCH", decision.reason_codes)

    def test_credentials_and_high_impact_delete_are_denied(self) -> None:
        credential = ActionRequest.from_dict(request_dict("read", uses_credentials=True))
        deletion = ActionRequest.from_dict(request_dict("delete", reversible=False))
        self.assertEqual(self.gate.decide(credential).decision, "deny")
        self.assertEqual(self.gate.decide(deletion).decision, "deny")

    def test_non_json_arguments_are_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            ActionRequest.from_dict(request_dict(arguments={"value": object()}))
        with self.assertRaises(PolicyError):
            ActionRequest.from_dict(request_dict(arguments={"value": math.nan}))


if __name__ == "__main__":
    unittest.main()
