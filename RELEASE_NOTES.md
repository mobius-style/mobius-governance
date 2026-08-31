# mobius-governance 0.8.2-alpha

This release fixes four defects **in our own 0.8.0/0.8.1 security fix**, found
by adversarial review of that fix. Two of them made claims in our own
documentation false. See `SECURITY.md`, advisory MG-2026-002.

- `FileApprovalLedger` was not atomic: check and append had no lock between
  them, so concurrent callers each consumed the same nonce. Measured at twelve
  concurrent processes, eight were granted. Agents issue tool calls in parallel
  and the CLI runs one process per call, so this was the normal case, not an
  edge case — the replay of MG-2026-001 reached through a different door.
- The approval summary was not injective, contrary to what we published. Only
  values were JSON-encoded, so a single untrusted source could be made to read
  as a trusted operator plus an untrusted page.
- Compound disclosure never fired on the `PreToolUse` adapter path, which is
  the only path a person actually reads.
- Abbreviated values carried a 64-bit hash prefix while three documents said
  "full SHA-256" and "cannot".

Also corrected: the HTTP app advertised `version="0.7.0"` — the version
withdrawn under MG-2026-001 — through `/openapi.json`; approval lifetime is now
bounded; and the `PreToolUse` reason string carries the approval surface.

**Breaking:** `not_after` is now capped (default 24 hours, reason code
`APPROVAL_LIFETIME_EXCEEDS_LIMIT`, configurable via `max_approval_lifetime`).
Long-lived grants that were previously accepted are refused. The approval
schema itself is unchanged from 0.8.0.

Evidence status: implementation verified; **efficacy not established**. The
held-out evaluation did not meet its predeclared minimum floors, and the
prospective study remains unexecuted. This release does not claim complete
prompt-injection prevention, certification, or production readiness. The
interior of a `Bash` command is not mediated; see `docs/MEDIATION_SCOPE.md`.
