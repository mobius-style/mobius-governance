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

## Advisory MG-2026-003 — retrieved context was read off a triage, not a scrub (fixed in 0.8.3)

**Affected:** 0.8.2 and earlier, whenever rcgov was installed and retrieved
context was supplied. **Fixed:** 0.8.3. **Severity:** medium. Nothing forbidden
reached the model; text that should have reached it silently did not, and the
metadata said otherwise.

`govern_context()` returned rcgov's `CLEAN_CONTEXT_PACK.md` as the governed
context. That artifact is what rcgov judged *placeable* for the task after
authority and priority appraisal. Without a commitments manifest — which this
package never supplies — a segment of plain prose with no provenance is routed
to `requires_review` and omitted, and the pack carries no marker for it. So
whenever at least one other segment was admitted, the reviewed segment vanished
from the prompt while the decision reported `governed=True`,
`rcgov_status="active"` and `context_empty=False`. Measured on 2026-09-19: an
ordinary English paragraph is dropped this way. When *nothing* was admitted the
empty-pack path fired correctly, which is why the defect was not visible in the
existing tests.

The metadata claim was the part that mattered: `admitted_segment_count` counted
the blobs handed to rcgov, not the segments the model saw, and a caller that
trusted it had no way to know text was missing.

0.8.3 rebuilds the context from rcgov's per-segment records: confirmed secrets,
injection patterns and block/quarantine gates become a placeholder with the
reason listed in `governed["excluded"]`; heuristic-only flags are kept and
listed; everything else is byte-identical. `admitted_segment_count` now means
what its name says, and `context_empty` is derived from it.

**Action required:** upgrade to 0.8.3. If your integration read
`governed["admitted_segment_count"]`, note its meaning changed from "blobs sent"
to "segments admitted". The same defect shipped in three sibling artifacts
(`moebiusT7/gemma-4-12b-mobius-custom` v1.0 and both `*-mobius-custom-c1`
wrappers) and is fixed there; `rcgov` 0.2.0 exposes `rebuild_bytes()` so the
correct primitive exists upstream.

## Advisory MG-2026-004 — a secret on a `#` line survived the excision of its own segment (fixed in 0.8.4)

**Affected:** 0.8.3, whenever rcgov was installed and retrieved context was
supplied. **Fixed:** 0.8.4 with rcgov 0.2.2. **Severity:** high for the inputs
it applies to — a credential reached the model and the metadata.

0.8.3 rebuilt the context from rcgov's records with its own copy of the rebuild
loop. When a segment was excised, the copy kept the segment's first line if it
looked like a Markdown heading. A commented line in a `.env` file or a shell
script — `# HF_TOKEN=…`, `# old: aws_secret_access_key = …` — looks like one.
So rcgov detected the secret, the segment was replaced by the placeholder, and
the line that held the secret was written back above the placeholder and
repeated in `governed["excluded"][].heading`. The decision said the segment was
excluded. It was, except for the secret.

This applied to every secret kind rcgov detects and the mandatory built-in
guard does not drop first. The guard drops a whole blob on its own rules
(RSA / EC / OPENSSH / DSA and unqualified private key headers, `AKIA`/`ASIA`
ids, `gh?_` tokens, bearer tokens, `api_key` / `access_token` / `secret_key` /
password assignments), so those never reached the rebuild; Slack tokens,
`token=` assignments, JWTs, URL credentials and every prefixed vendor token
did. Measured on 0.8.3 with 20 secret kinds in 24 placements: 336 of 454
documents returned the secret. The same copy of the loop shipped in three sibling
artifacts and in rcgov's own `rebuild_bytes`; rcgov 0.2.1 has the incident
report.

A second, older gap is closed with it: **the built-in guard had no rule for AWS
secret access keys.** In `aws_secret_access_key = …` the word `secret` is
followed by `_access_key`, so the `secret_key` assignment rule did not match,
and the 40-character value has no prefix. Without rcgov the key was admitted;
with rcgov 0.2.0 it was flagged only as a high-entropy token, which is kept.

0.8.4:

- The rebuild is `rcgov.service.rebuild_records` (rcgov 0.2.2). The local copy
  is deleted. An rcgov without that function is not papered over with a local
  rebuild: `require_rcgov=True` fails closed with
  `reason="rcgov_too_old_or_broken"`; with `require_rcgov=False` the context
  passes the built-in guard only and the decision says `status="degraded"`,
  `rcgov_status="error"`. Both carry `rcgov_minimum`. A missing rcgov keeps its
  0.8.3 reasons.
- The heading line of an excised segment is removed when it carries any
  finding at all, including a path or a long token that would be kept in body
  text; `excluded[].heading` then shows a marker. A heading that is itself an
  injection phrase is removed; 0.8.3 kept it.
- Policy `2026-09-29.1` adds the rule `aws_secret_access_key`. The guard
  case-folds its input, so the rule cannot ask for mixed case; it asks for 40
  characters of the base64 alphabet with a digit and a character that is not a
  hexadecimal digit, within 24 characters of the label. A 40-digit hex hash
  after the words "secret key" is admitted. Measured: 3,000 of 3,000 random
  keys in ten label forms dropped; 3 of 65 benign texts dropped, each a
  40-character alphanumeric id right after the words "secret key". It misses
  a label more than 24 characters away, a value with no digit (about one
  random key in a thousand), and labels in other languages.

Measured before release: with the 0.8.3 `core.py` and rcgov 0.2.2, the new
test `test_secret_on_a_comment_line_is_not_kept_as_the_heading` fails — the
token is in the text; with 0.8.4 it is absent from the text and from the
metadata, and the neighbouring paragraphs are kept.

**What is not fixed.** The guard's rules are still a short list: it has no
rule for `sk-`, `hf_`, GitLab, Google or Stripe keys, Slack tokens, `token=`
assignments, JWTs, URL credentials, `github_pat_` tokens or encrypted / PGP
private key headers, and relies on rcgov for them. Without rcgov installed —
or, in optional mode, with an rcgov older than 0.2.2 — those pass. If you ran
0.8.3 with rcgov 0.2.0 or 0.2.1 and `require_rcgov=False`, upgrading only this
package **loses** rcgov's body-level exclusions until rcgov is upgraded too;
the decision reads `degraded`. Upgrade both. The guard's full scan is slow
and was before: measured on 0.8.3, a 1.9 MB segment takes 60–104 s, growing
linearly with size; at 100 KB and 400 KB 0.8.4 is within 2 % of 0.8.3, and
the new rule adds at most 0.24 s at 1.9 MB. rcgov 0.2.1's README lists the forms
its own patterns miss (short passwords, passwords with symbols, a key with no
label); they pass here too.

**Action required:** upgrade to 0.8.4 and to rcgov 0.2.3 (0.2.2 is the
minimum; `pip install "mobius-governance[govern]"` pins the tag `v0.2.3`). If you stored decisions
from 0.8.3, treat `governed["excluded"][].heading` in them as possibly holding
the secret that caused the exclusion. If you pinned the policy hash, it changed.

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

