# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""A consumption ledger that is not atomic does not enforce single use.

Agents issue tool calls in parallel and the CLI runs one process per call, so
concurrent consumption of the same grant is the normal case. Before 0.8.2 the
file ledger read the whole file and then appended, with nothing between: twelve
concurrent processes presenting one nonce each received permission to act.
That is the replay MG-2026-001 described, reached through a different door.
"""
from __future__ import annotations

import multiprocessing
import tempfile
import threading
import unittest
from pathlib import Path

from mobius_governance.actions import Approval, FileApprovalLedger, InMemoryApprovalLedger

APPROVAL = {
    "schema_version": "mobius.action-approval.v2",
    "approval_id": "concurrent",
    "channel": "trusted_user",
    "approved": True,
    "action_digest": "a" * 64,
    "nonce": "N" * 32,
    "audience": "host",
    "not_after": 4102444800,
}


def _consume(path: str, barrier, results) -> None:
    approval = Approval.from_dict(APPROVAL)
    barrier.wait()
    results.put(FileApprovalLedger(path)(approval))


class LedgerConcurrencyTests(unittest.TestCase):
    def test_concurrent_processes_consume_a_nonce_exactly_once(self) -> None:
        workers = 12
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "ledger.jsonl")
            barrier = multiprocessing.Barrier(workers)
            results: multiprocessing.Queue = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(target=_consume, args=(path, barrier, results))
                for _ in range(workers)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=30)
            granted = sum(results.get() for _ in range(workers))
            recorded = sum(1 for line in open(path, encoding="utf-8") if line.strip())
        self.assertEqual(granted, 1, "one grant authorised more than one action")
        self.assertEqual(recorded, 1, "the ledger recorded more than one consumption")

    def test_in_memory_ledger_holds_a_lock_across_check_and_add(self) -> None:
        """Assert the critical section directly, not by racing threads.

        A thread race is not evidence here: `set.__contains__` followed by
        `set.add` does not yield the GIL between them, so an unlocked ledger
        passes a concurrency test while still being unsafe. Measured on the
        unlocked 0.8.1 implementation: 0 failures in 50 runs at any switch
        interval. The property to check is that the lock is held while the
        membership test and the insertion happen, so we observe the lock state
        from inside the operation.
        """
        ledger = InMemoryApprovalLedger()
        approval = Approval.from_dict(APPROVAL)
        observed: list[bool] = []
        real_add = ledger._consumed.add

        class Probe(set):
            def __contains__(self, item):
                observed.append(ledger._lock.locked())
                return set.__contains__(self, item)

            def add(self, item):
                observed.append(ledger._lock.locked())
                return set.add(self, item)

        probe = Probe()
        ledger._consumed = probe
        self.assertTrue(ledger(approval))
        self.assertTrue(observed, "the ledger did not consult its store")
        self.assertTrue(all(observed), "check and add ran outside the lock")
        self.assertFalse(ledger(approval))

    def test_a_lost_ledger_restores_replay_and_that_is_documented(self) -> None:
        """Deleting the ledger reopens replay: an operational property, not a bug.

        The ledger cannot defend its own storage. This test exists so the fact
        stays visible, and so that the security documentation keeps saying it.
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            approval = Approval.from_dict(APPROVAL)
            self.assertTrue(FileApprovalLedger(str(path))(approval))
            self.assertFalse(FileApprovalLedger(str(path))(approval))
            path.unlink()
            self.assertTrue(FileApprovalLedger(str(path))(approval))
        security = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text(encoding="utf-8")
        collapsed = " ".join(security.split())
        self.assertIn("lost ledger silently restores replay", collapsed)


if __name__ == "__main__":
    unittest.main()
