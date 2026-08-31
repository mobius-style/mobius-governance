# Changelog

## 0.8.0-alpha — 2026-08-31

**Security fix (advisory MG-2026-001): approvals now bind to one action
instance, not to an action class.** See `SECURITY.md`.

- **Breaking:** approval schema is `mobius.action-approval.v2` and requires
  `nonce`, `audience`, and `not_after`. v1 approvals are rejected.
- **Breaking:** promoting an `ask` to `allow` now requires an approval ledger
  and a configured gate `audience` in addition to the host-side verifier.
  Each missing input fails closed with its own reason code.
- Added `InMemoryApprovalLedger` and `FileApprovalLedger` (append-only,
  fsynced) as reference consumption ledgers.
- Added `--approval-ledger` and `--approval-audience` to `mobius-governance
  action`; `--approval` without them no longer promotes an action.
- A grant refused for any reason other than consumption stays unspent.
- Added eight regression tests, including the replay case that the shipped
  0.7.0 code failed (59 unit tests, up from 51).
- Detector, policy (130 rules), and contract suite (105 cases) are unchanged.

## Unreleased

- Added a human-readable approval surface. Every decision now carries a
  `summary` rendered from the digested structure, so what an approver reads is
  derived from what they authorise. The rendering is injective with respect to
  the digest (abbreviated values carry the full value's SHA-256 and length),
  argument values are JSON-encoded so they cannot forge summary lines, and one
  approval covering a chained command is disclosed as compound.
- Added `tests/test_approval_surface.py` (7 tests, 75 total), calibrated
  against four broken renderings: abbreviation without a hash, raw value
  rendering that permits newline injection, a dropped provenance line, and
  removed compound disclosure.
- Declared the mediation boundary in `docs/MEDIATION_SCOPE.md`: eleven
  `PreToolUse` tools in scope, unrecognised tools fail closed, and the interior
  of a `Bash` command plus effect paths that never reach the adapter are stated
  as out of scope rather than left implicit.
- Added `tests/test_mediation_coverage.py` (9 bypass tests, 68 total). The
  declared set is recovered from the classifier by AST, so the document cannot
  drift from the implementation. Calibrated against three deliberately broken
  builds — unknown tools failing open, a removed delegation branch, and an
  effectful tool downgraded to allow — each of which the suite detects.

## 0.7.0-alpha — 2026-08-28

- Added a bounded four-pass English/Japanese structural context scanner.
- Added typed action mediation and a Claude Code `PreToolUse` adapter.
- Made policy identity, resolved path, profile, and active rule count observable.
- Preserved fail-closed behavior for missing or malformed required policy.
- Published an implementation-only snapshot; efficacy remains not established.

