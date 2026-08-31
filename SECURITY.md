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

## Advisory MG-2026-002 — the 0.8.0/0.8.1 fix was incomplete (fixed in 0.8.2)

**Affected:** 0.8.0 and 0.8.1. **Fixed:** 0.8.2. **Severity:** high for hosts
using `FileApprovalLedger`; the approval-surface defects are high wherever a
human reads the summary to decide.

Adversarial review of our own fix found four defects in it. We publish them in
full because two of them made claims in our own documentation false.

1. **The file ledger was not atomic.** `FileApprovalLedger` read the ledger and
   then appended, with no lock between. Concurrent callers each saw a ledger
   without the nonce and each concluded the grant was unspent. Measured: twelve
   concurrent processes presenting one nonce, eight received permission. Agents
   issue tool calls in parallel and the CLI runs one process per call, so this
   is the normal case. This is the replay of MG-2026-001 reached through a
   different door. Fixed with an exclusive lock (`flock`) spanning check and
   append; `InMemoryApprovalLedger` is likewise now atomic.
2. **The approval summary was not injective, contrary to our claim.** Only
   values were JSON-encoded; `operation`, `tool`, argument keys, and
   `source_ids` were interpolated raw. Two requests with different digests
   could render identically, and a single untrusted source could be made to
   read as a trusted operator plus an untrusted page. Fixed by encoding every
   interpolated element and rendering sources one per line with a count.
3. **Compound disclosure never fired on the adapter path.** The scan covered
   only top-level string arguments, but the `PreToolUse` adapter puts the
   command in `target`. Chained commands reached approvers with no warning.
   Fixed by scanning `target` and recursing into nested lists and mappings, by
   adding `<(`, `>(`, and `$'` to the token set, and by correcting the adapter:
   it truncated the command at 10,000 characters and preferred `file_path` over
   `command`, either of which pushed the chaining operators out of view. The
   adapter now forwards the markers it finds in the fields whose value is
   executed (`command`, `cmd`, `script`, `argv`, `args`, `shell`), at any
   nesting depth. Two exclusions are deliberate and therefore undisclosed by
   design: a bare `&`, because it appears in ordinary query strings; and
   command-bearing fields under other names, because scanning every field made
   the warning fire on most ordinary calls — file content, edit replacements,
   and search patterns legitimately contain newlines and pipes. A warning that
   fires constantly is trained away, which is the same failure as not warning.
   A tool that passes a command under an unrecognised key is not disclosed as
   compound; such tools are outside the declared set and reach `ask` as
   `unknown`.
4. **Abbreviated values carried a 64-bit hash prefix while the documentation
   said "full SHA-256" and "cannot".** Fixed by emitting the full digest.

Also corrected: the HTTP app advertised `version="0.7.0"` — the version
withdrawn under MG-2026-001 — through `/openapi.json`; and `not_after` had no
ceiling, so a self-asserted expiry could be perpetual (now bounded, default 24
hours).

### Threat model for approvals — read this before relying on the ledger

The single-use ledger defends against **replay of a captured approval**. It does
not defend against **forgery of a new approval**. Authenticity rests entirely on
the host-side `approval_verifier`, and **the verifier shipped in this repository
is a stub that returns true** (`cli.py`): it marks the local-operator boundary,
it does not authenticate anything. Anyone who can write an approval file can
mint fresh nonces without limit. A deployment that needs approvals to be
unforgeable must supply a verifier that checks a signature over the whole
approval, including the nonce.

The ledger also cannot defend its own storage: deleting or truncating it
restores replay, and the governed agent has `Bash`, which is gated at `ask`
rather than denied. Independently administered, append-only retention is not a
nicety here.

## Supported release

Version 0.8.x is an alpha implementation. Security fixes may change policy
behavior; pin exact versions and rerun your own regression set before updating.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting, which is
enabled on this repository: open the Security tab and choose *Report a
vulnerability*. Do not include credentials, private prompts, customer data, or
live exploit payloads in a public issue.

We publish defects in our own security machinery, including defects in our own
fixes — MG-2026-002 is an advisory about MG-2026-001's remedy. Expect the same
treatment for anything reported here.

**What this project can promise.** Advisories are published in `SECURITY.md`,
in the changelog, and in GitHub Releases, and superseded releases are annotated
in place. There is no individual notification channel: this is an unfunded
alpha with no subscriber list, and neither the AGPL grant nor a commercial
licence adds a duty to contact anyone. Watch releases if you need to know.

## Scope boundary

This component does not claim complete prompt-injection prevention. It assumes
the caller still enforces least privilege, explicit approval for consequential
actions, sandboxing, audit logs, and rollback. Scanner admission is never
authorization for a tool action.

