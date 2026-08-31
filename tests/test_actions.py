from __future__ import annotations

import math
import unittest

from mobius_governance.actions import ACTION_SCHEMA, APPROVAL_SCHEMA, ActionGate, ActionRequest, Approval, InMemoryApprovalLedger
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
            "nonce": "n" * 32,
            "audience": "test-host",
            "not_after": 4600,
        })
        decision = ActionGate(
            GuardEngine.from_path(), approval_verifier=lambda supplied, action: True,
            approval_ledger=InMemoryApprovalLedger(), audience="test-host",
            clock=lambda: 1000.0,
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
            "nonce": "n" * 32,
            "audience": "test-host",
            "not_after": 4600,
        })
        # audience/ledger are supplied so this test isolates the verifier rule;
        # each missing host input has its own dedicated test below.
        decision = ActionGate(
            GuardEngine.from_path(),
            approval_ledger=InMemoryApprovalLedger(),
            audience="test-host",
            clock=lambda: 1000.0,
        ).decide(request, approval)
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
            "nonce": "n" * 32,
            "audience": "test-host",
            "not_after": 4600,
        })
        decision = ActionGate(
            GuardEngine.from_path(),
            approval_verifier=lambda supplied, action: True,
            approval_ledger=InMemoryApprovalLedger(), audience="test-host",
            clock=lambda: 1000.0,
        ).decide(second, approval)
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

    # --- v0.8.0 security fix: approvals bind to an action INSTANCE ---

    def _instance_fixture(self):
        request = ActionRequest.from_dict(request_dict("write"))
        approval = Approval.from_dict({
            "schema_version": APPROVAL_SCHEMA,
            "approval_id": "approval-1",
            "channel": "trusted_user",
            "approved": True,
            "action_digest": request.digest,
            "nonce": "n" * 32,
            "audience": "test-host",
            "not_after": 4600,
        })
        gate = ActionGate(
            GuardEngine.from_path(),
            approval_verifier=lambda supplied, action: True,
            approval_ledger=InMemoryApprovalLedger(),
            audience="test-host",
            clock=lambda: 1000.0,
        )
        return gate, request, approval

    def test_replayed_approval_is_refused(self) -> None:
        """The defect fixed in 0.8.0: one grant authorised every later identical action."""
        gate, request, approval = self._instance_fixture()
        self.assertEqual(gate.decide(request, approval).decision, "allow")
        for _ in range(3):
            repeat = gate.decide(request, approval)
            self.assertEqual(repeat.decision, "ask")
            self.assertIn("APPROVAL_ALREADY_CONSUMED", repeat.reason_codes)

    def test_approval_without_ledger_is_not_promoted(self) -> None:
        gate, request, approval = self._instance_fixture()
        gate.approval_ledger = None
        decision = gate.decide(request, approval)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_LEDGER_UNAVAILABLE", decision.reason_codes)

    def test_approval_for_another_audience_is_refused(self) -> None:
        gate, request, approval = self._instance_fixture()
        gate.audience = "other-host"
        decision = gate.decide(request, approval)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_AUDIENCE_MISMATCH", decision.reason_codes)

    def test_gate_without_audience_never_promotes(self) -> None:
        gate, request, approval = self._instance_fixture()
        gate.audience = None
        decision = gate.decide(request, approval)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_AUDIENCE_UNAVAILABLE", decision.reason_codes)

    def test_expired_approval_is_refused(self) -> None:
        gate, request, approval = self._instance_fixture()
        gate.clock = lambda: 4601.0
        decision = gate.decide(request, approval)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_EXPIRED", decision.reason_codes)

    def test_rejected_approval_does_not_spend_the_nonce(self) -> None:
        """A grant refused for any other reason stays unspent and re-presentable."""
        gate, request, approval = self._instance_fixture()
        gate.audience = "other-host"
        self.assertEqual(gate.decide(request, approval).decision, "ask")
        gate.audience = "test-host"
        self.assertEqual(gate.decide(request, approval).decision, "allow")

    def test_approval_lifetime_is_bounded(self) -> None:
        """A self-asserted expiry with no ceiling is effectively perpetual."""
        gate, request, _ = self._instance_fixture()
        far = Approval.from_dict({
            "schema_version": APPROVAL_SCHEMA, "approval_id": "long",
            "channel": "trusted_user", "approved": True,
            "action_digest": request.digest, "nonce": "n" * 32,
            "audience": "test-host", "not_after": 4102444800,
        })
        decision = gate.decide(request, far)
        self.assertEqual(decision.decision, "ask")
        self.assertIn("APPROVAL_LIFETIME_EXCEEDS_LIMIT", decision.reason_codes)
        # Refusing on lifetime must not spend the grant.
        gate.max_approval_lifetime = None
        self.assertEqual(gate.decide(request, far).decision, "allow")

    def test_v1_approval_without_nonce_is_rejected(self) -> None:
        """The old replayable schema can no longer be presented at all."""
        request = ActionRequest.from_dict(request_dict("write"))
        with self.assertRaises(PolicyError):
            Approval.from_dict({
                "schema_version": "mobius.action-approval.v1",
                "approval_id": "legacy",
                "channel": "trusted_user",
                "approved": True,
                "action_digest": request.digest,
            })

    def test_short_nonce_is_rejected(self) -> None:
        request = ActionRequest.from_dict(request_dict("write"))
        with self.assertRaises(PolicyError):
            Approval.from_dict({
                "schema_version": APPROVAL_SCHEMA,
                "approval_id": "weak",
                "channel": "trusted_user",
                "approved": True,
                "action_digest": request.digest,
                "nonce": "short",
                "audience": "test-host",
                "not_after": 4600,
            })


if __name__ == "__main__":
    unittest.main()
