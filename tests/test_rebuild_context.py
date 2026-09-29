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
SECRET = "export HF_TOKEN=hf_TESTFIXTUREABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 && curl -H 'Authorization: Bearer' https://example.invalid"
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




# 0.8.4 — the rebuild is rcgov's own (MG-2026-004). TEST FIXTURE values, not credentials.
COMMENT_SECRET = "hf_TESTaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"
COMMENT_BLOB = ("Deploy notes for the staging box.\n\n"
                f"# HF_TOKEN {COMMENT_SECRET}\nREGION=us-east-1\n\n"
                "## Plan\n\nThe release ships on Friday.\n")


@unittest.skipUnless(HAVE_RCGOV, "rcgov not installed")
class HeadingLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardEngine.from_path()

    def test_secret_on_a_comment_line_is_not_kept_as_the_heading(self) -> None:
        """0.8.3 excised the segment and kept its first line — the line with the secret."""
        text, meta = govern_context([COMMENT_BLOB], "Summarize", guard_engine=self.engine, require_rcgov=True)
        self.assertEqual(meta["rcgov_status"], "active")
        self.assertNotIn(COMMENT_SECRET, text)
        self.assertNotIn(COMMENT_SECRET, repr(meta))
        self.assertIn("The release ships on Friday.", text)
        self.assertIn("Deploy notes for the staging box.", text)
        self.assertTrue(any("huggingface_token" in e["reason"] for e in meta["excluded"]))

    def test_clean_heading_of_an_excised_segment_is_kept(self) -> None:
        blob = f"Intro line.\n\n## Access\n\nuse {COMMENT_SECRET} here\n\n## Plan\n\nShip.\n"
        text, meta = govern_context([blob], "Summarize", guard_engine=self.engine, require_rcgov=True)
        self.assertIn("## Access\n", text)
        self.assertNotIn(COMMENT_SECRET, text)
        self.assertEqual(set(meta["excluded"][0]), {"segment", "heading", "reason"})

    def test_rcgov_without_rebuild_records_is_treated_as_unavailable(self) -> None:
        """An rcgov older than 0.2.2 must not be papered over with a local rebuild."""
        from unittest import mock
        import rcgov.service as service
        with mock.patch.object(service, "rebuild_records", create=True):
            delattr(service, "rebuild_records")
            text, meta = govern_context([FACT], "Explain", guard_engine=self.engine, require_rcgov=True)
            self.assertEqual((text, meta["reason"], meta["fail_closed"]),
                             ("", "rcgov_too_old_or_broken", True))
            self.assertEqual(meta["rcgov_minimum"], "0.2.2")
            text, meta = govern_context([FACT], "Explain", guard_engine=self.engine, require_rcgov=False)
            self.assertEqual(meta["mode"], "builtin_guard_only")
            self.assertEqual((meta["status"], meta["rcgov_status"]), ("degraded", "error"))
            self.assertEqual(meta["reason"], "rcgov_optional_too_old_or_broken")

    def test_missing_rcgov_keeps_its_own_reason(self) -> None:
        import sys
        from unittest import mock
        with mock.patch.dict(sys.modules, {"rcgov.pipeline": None}):
            text, meta = govern_context([FACT], "Explain", guard_engine=self.engine, require_rcgov=True)
            self.assertEqual((text, meta["reason"]), ("", "rcgov_unavailable"))
            text, meta = govern_context([FACT], "Explain", guard_engine=self.engine, require_rcgov=False)
            self.assertEqual((meta["status"], meta["reason"]), ("active", "rcgov_optional_unavailable"))


class BuiltinAwsSecretRuleTests(unittest.TestCase):
    """The mandatory guard had no rule for AWS secret access keys."""

    AWS_EXAMPLE = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   # AWS's documentation EXAMPLE key

    def setUp(self) -> None:
        self.engine = GuardEngine.from_path()

    def test_labelled_aws_secret_key_is_dropped(self) -> None:
        for form in ("aws_secret_access_key = {}", "AWS_SECRET_ACCESS_KEY={}", "Secret access key: {}",
                     "# old: aws_secret_access_key = {}", '"SecretAccessKey": "{}"'):
            decision = self.engine.scan(form.format(self.AWS_EXAMPLE))
            self.assertEqual(decision.decision, "drop", form)
            self.assertIn("aws_secret_access_key", {h.rule_id for h in decision.hits}, form)

    def test_hashes_and_prose_about_secret_keys_are_admitted(self) -> None:
        for text in ("The secret key was rotated in 3f2a9c1e7b4d8a6f0e5c2b9d1a7f4e8c6b3d0a59.",
                     "Rotate the secret access key every ninety days and store it in the vault.",
                     "The secret key fingerprint is 0123456789012345678901234567890123456789."):
            self.assertEqual(self.engine.scan(text).decision, "admit", text)


if __name__ == "__main__":
    unittest.main()
