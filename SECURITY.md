# Security policy

## Advisory MG-2026-001 — replayable approvals (fixed in 0.8.0)

**Affected:** 0.7.0 and earlier. **Fixed:** 0.8.0. **Severity:** high for any
host that persisted or transported approval objects.

In 0.7.0 an `Approval` was bound only to the canonical action digest. A digest
identifies an action *class*, not one execution of it, and the gate kept no
record of which grants had been spent. The same approval object therefore
re-authorised every later action with identical parameters, without limit. We
confirmed this against the published 0.7.0 code: three consecutive `decide()`
calls with one approval returned `allow / EXACT_ACTION_APPROVED` each time. The
`--approval` CLI path was the practical exposure, since an approval file could
be replayed indefinitely; the HTTP endpoint was never affected, because it has
always refused caller-supplied approvals.

0.8.0 binds an approval to one action *instance*. `mobius.action-approval.v2`
adds a `nonce`, an `audience`, and a `not_after` expiry, and promotion now also
requires a consumption ledger that records the spent nonce. Every missing host
input fails closed with its own reason code — `APPROVAL_LEDGER_UNAVAILABLE`,
`APPROVAL_AUDIENCE_UNAVAILABLE`, `APPROVAL_AUDIENCE_MISMATCH`,
`APPROVAL_EXPIRED`, `APPROVAL_ALREADY_CONSUMED` — and a grant refused for any
reason other than consumption stays unspent. v1 approvals are rejected outright
rather than accepted without a nonce.

**Action required:** upgrade to 0.8.0, reissue any stored approvals in the v2
schema, and supply a durable ledger. `FileApprovalLedger` is a local-operator
convenience; a deployment that must not lose the record needs independently
administered, append-only retention, because a lost ledger silently restores
replay.

## Supported release

Version 0.8.x is an alpha implementation. Security fixes may change policy
behavior; pin exact versions and rerun your own regression set before updating.

## Reporting a vulnerability

Do not include credentials, private prompts, customer data, or live exploit
payloads in a public issue. Use GitHub's private vulnerability reporting for
this repository when available. If that channel is unavailable, open a public
issue containing only a request for a private contact channel.

## Scope boundary

This component does not claim complete prompt-injection prevention. It assumes
the caller still enforces least privilege, explicit approval for consequential
actions, sandboxing, audit logs, and rollback. Scanner admission is never
authorization for a tool action.

