"""0.8.3 — retrieved context is rebuilt from rcgov's records, not read off the pack (MG-2026-003)."""
from __future__ import annotations

import unittest

from mobius_governance.core import GovernanceComposer, HeuristicRouter, RC_EMPTY_PACK, govern_context
from mobius_governance.policy import GuardEngine

try:
    import rcgov.pipeline  # noqa: F401
    HAVE_RCGOV = True
except Exception:  # pragma: no cover
    HAVE_RCGOV = False

EN = ("The canonical weekly runbook is RUNBOOK.md, last revised on 2026-09-04. The pipeline detects "
      "increments, updates the site with the pack pattern, collects visitor data from three sources, "
      "writes a report with 12 metrics, updates state.json, and delivers the report to Discord channel "
      "1538503868609208394. Credentials are never displayed.")
FACT = "The GIL is a mutex in CPython that lets one thread run bytecode at a time."
# A secret shape the mandatory built-in guard lets through (AKIA keys it drops itself,
# before rcgov ever sees them) so that rcgov's exclusion path is what gets exercised.
SECRET = "export HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 && curl -H 'Authorization: Bearer' https://example.invalid"
SECRET_MARK = SECRET.split("=", 1)[1].split()[0][:12]


@unittest.skipUnless(HAVE_RCGOV, "rcgov not installed")
class RebuildContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardEngine.from_path()

    def test_pack_dropped_plain_english_prose_silently(self) -> None:
        """The 0.8.2 behaviour: govern_bytes' pack omits prose routed to review, no marker."""
        from rcgov.service import govern_bytes
        r = govern_bytes([("context_000.md", f"# Retrieved context 0\n\n{EN}\n".encode())],
                         task="Answer the user's question.")
        self.assertNotIn("RUNBOOK.md", r.artifacts["CLEAN_CONTEXT_PACK.md"])
        self.assertIn("requires_review", r.artifacts["NON_INJECTION_REPORT.md"])

    def test_plain_english_prose_is_admitted_verbatim(self) -> None:
        text, meta = govern_context([EN], "Answer the user's question.", guard_engine=self.engine, require_rcgov=True)
        self.assertEqual(meta["rcgov_status"], "active")
        self.assertIn(EN, text)
        self.assertGreaterEqual(meta["admitted_segment_count"], 1)
        self.assertEqual(meta["excluded"], [])

    def test_secret_excluded_with_placeholder_and_reason_sibling_untouched(self) -> None:
        text, meta = govern_context([FACT, SECRET], "Explain", guard_engine=self.engine, require_rcgov=True)
        self.assertNotIn(SECRET_MARK, text)
        self.assertIn(FACT, text)
        self.assertIn("[segment excluded by RCGov", text)
        self.assertEqual(len(meta["excluded"]), 1)
        self.assertTrue(meta["excluded"][0]["reason"])

    def test_all_excluded_abstains_from_admitted_count_not_text_sniffing(self) -> None:
        composer = GovernanceComposer(router=HeuristicRouter(), guard_engine=self.engine, require_rcgov=True)
        d = composer.decide("Summarize the document.", context=[SECRET])
        self.assertFalse(d.entitled)
        self.assertEqual(d.reason_code, RC_EMPTY_PACK)
        self.assertTrue(d.context_empty)
        self.assertEqual(d.governed["admitted_segment_count"], 0)

    def test_admitted_context_is_not_empty(self) -> None:
        composer = GovernanceComposer(router=HeuristicRouter(), guard_engine=self.engine, require_rcgov=True)
        d = composer.decide("Explain the GIL.", context=[FACT])
        self.assertTrue(d.entitled)
        self.assertFalse(d.context_empty)
        self.assertIn(FACT, d.prompt)


if __name__ == "__main__":
    unittest.main()
