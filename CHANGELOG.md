# Changelog

## 0.8.3-alpha — 2026-09-20

**Security fix (advisory MG-2026-003): retrieved context was read off rcgov's
Clean Context Pack, which is a triage, not a scrub.** See `SECURITY.md`.

- `govern_context()` handed the model `CLEAN_CONTEXT_PACK.md`. That artifact is
  what rcgov judged *placeable* after authority and priority appraisal. Without
  a commitments manifest a segment of plain prose with no provenance is routed
  to `requires_review` and simply omitted, with no marker in the pack — so
  whenever any other segment was admitted, that text vanished while
  `governed=True`, `rcgov_status="active"`, and `context_empty=False`. Measured:
  an English paragraph of ordinary prose is dropped this way.
- Retrieved context is now **rebuilt segment by segment** from rcgov's records
  (`rcgov.pipeline.run`): confirmed secrets, injection patterns and block /
  quarantine gates are replaced by a placeholder and listed in
  `governed["excluded"]` with their reason; heuristic-only flags
  (`high_entropy_token` — ids, hashes, paths) are kept and listed in
  `governed["retained_flagged"]`; everything else is byte-identical. Spans are
  verified against rcgov's own records; a manifest that disagrees with them is
  an error, and `require_rcgov` decides fail-closed vs degraded as before.
- `context_empty` is now decided from `governed["admitted_segment_count"]`
  when rcgov ran, not by sniffing the text for `_(none)_` placeholders.
  `admitted_segment_count` is now the number of segments that reached the model,
  not the number of input blobs handed to rcgov.
- The mandatory built-in guard, the fail-closed semantics of `require_rcgov`,
  and the degraded mode when rcgov is optional and fails are unchanged.
- `tests/test_rebuild_context.py` pins the 0.8.2 drop and every branch of the
  rebuild; the two `test_core_server.py` fixtures that mocked
  `rcgov.service.govern_bytes` now mock `rcgov.pipeline.run`, which is the
  dependency the code actually has.
- Found on 2026-09-19 while the sibling Gemma-4 wrappers were being used as the
  author's own daily session-record clerk; the same defect was shipped in
  `gemma-4-12b-mobius-custom` v1.0 and both C1 wrappers, all re-released.
  `rcgov` 0.2.0 adds `rebuild_bytes()` so future callers need not reimplement
  this.

## 0.8.2-alpha — 2026-08-31

**Security fix (advisory MG-2026-002): the 0.8.0/0.8.1 fix was incomplete.**
Adversarial review of our own fix found four defects in it; two made claims in
our own documentation false. See `SECURITY.md`.

- `FileApprovalLedger` was not atomic: check and append had no lock between
  them, so concurrent callers each consumed the same nonce. Measured at twelve
  concurrent processes: eight were granted. Fixed with `flock` spanning the
  critical section; `InMemoryApprovalLedger` is now atomic too.
- The approval summary was not injective. Only values were JSON-encoded;
  `operation`, `tool`, argument keys, and `source_ids` were interpolated raw,
  so different actions could render identically and one untrusted source could
  read as two, one of them trusted. Every interpolated element is now encoded
  and sources render one per line with a count.
- Compound disclosure never fired on the `PreToolUse` adapter, which puts the
  command in `target` while the scan covered only string arguments. The scan
  now covers `target` and recurses into nested lists and mappings; `&`, `<(`,
  `>(`, and `$'` were added to the token set.
- Abbreviated values carried a 64-bit hash prefix while three documents claimed
  the full SHA-256; the full digest is now emitted.
- The HTTP app advertised `version="0.7.0"` — withdrawn under MG-2026-001 —
  through `/openapi.json`. It now tracks the package version.
- `not_after` had no ceiling; approval lifetime is now bounded (default 24h,
  reason code `APPROVAL_LIFETIME_EXCEEDS_LIMIT`).
- The `PreToolUse` reason string now carries the approval surface, with values
  elided to their length so the host's own display of the same call is not
  duplicated onto a logged channel. This is de-duplication, not secrecy: no
  digest of a value is emitted, because an unsalted digest of a low-entropy
  value is recoverable by search. The elided rendering is not injective.
- Replaced example-based approval-surface tests with property tests over an
  adversarial corpus, and added ledger concurrency tests, plus tests that lock
  the compound scan in both directions. 82 tests; the seven example-based
  approval-surface tests were removed as superseded, and their docstring
  asserted the injectivity property this advisory found to be false.

## 0.8.1-alpha — 2026-08-31

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

## 0.7.0-alpha — 2026-08-28

- Added a bounded four-pass English/Japanese structural context scanner.
- Added typed action mediation and a Claude Code `PreToolUse` adapter.
- Made policy identity, resolved path, profile, and active rule count observable.
- Preserved fail-closed behavior for missing or malformed required policy.
- Published an implementation-only snapshot; efficacy remains not established.

