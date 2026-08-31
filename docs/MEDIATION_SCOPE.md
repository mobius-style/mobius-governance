# Mediation scope

This document states exactly what the action gate mediates, and what it does
not. It exists because "complete mediation" is a claim that is only meaningful
relative to a declared boundary: a gate that mediates everything it knows about
still admits whatever it was never shown.

The scope below is enforced by `tests/test_mediation_coverage.py`, which
derives the declared tool set from the classifier source rather than from this
prose, so the two cannot drift apart silently.

## In scope

The `PreToolUse` adapter for a local development agent. Eleven tool names are
classified into typed operations:

| Tool | Operation | Decision with default policy |
|---|---|---|
| `Read` | read | allow |
| `Glob`, `Grep` | search | allow |
| `WebSearch` | search (external) | allow |
| `WebFetch` | download (external) | ask |
| `Write` | write | ask |
| `Edit`, `NotebookEdit` | edit | ask |
| `Bash` | execute / delete / admin | ask or deny |
| `Agent`, `Task` | execute | ask |

Within this set the tests assert three properties: every declared tool receives
a decision with a canonical digest; no effect-bearing declared tool is admitted
without approval; and delegation to a child agent is itself a mediated effect,
not a way to escape the boundary.

## Fail-closed by default

Any tool name outside the declared set classifies as `unknown` and is never
*automatically* admitted: the default policy maps `unknown` to `ask`, so an
unrecognised tool needs an approval like any other consequential action. It is
not denied outright, so a host that supplies approvals can approve a tool this
adapter has never seen. This covers MCP server tools, future first-party tools,
plugins, and near-misses of declared names, including case variations, trailing
whitespace, and Unicode homoglyphs. The tests probe each of these explicitly. Malformed
payloads and non-`PreToolUse` events raise rather than return a decision, so a
caller cannot obtain a permissive default by sending a broken request.

## Out of scope — stated, not assumed

**The interior of a `Bash` command.** `Bash` is mediated as one opaque action.
Its command string is inspected by pattern to raise the operation to `delete` or
`admin` where it can, and to mark network-reaching commands external, but a
shell string can express arbitrary effects and can be obfuscated without limit.
`echo <base64> | base64 -d | sh` classifies as a plain `execute`. It is still
gated — it reaches `ask` and is never admitted without an approval — but the
gate cannot see what the shell
will do. `tests/test_mediation_coverage.py` asserts this limitation as a
passing test so that it cannot be quietly lost.

Reducing this hole is not a matter of adding patterns; it requires either
decomposing shell execution into typed effects or confining it by OS-level
isolation and egress control. Both are outside this release.

**Effect paths that never reach the adapter.** Anything that causes an effect
without a `PreToolUse` call is unmediated by construction: adversarial text
that reaches model weights through a training or fine-tuning pipeline, and
adversarial text read directly by a human, whose persuasion is an effect
requiring no tool call at all. These are named in the foundations paper as
explicitly outside the one-sidedness claim.

**Everything downstream of an approved action.** An approved `send` can carry
harmful content; an action granularity chosen too coarse hides several concrete
effects inside one approved digest; covert channels can ride inside legitimate
traffic. Mediation makes the path finite and the decision checkable. It does
not make the content of a permitted act harmless.

## The approval surface

A correct digest is not consent. If an approver is shown a rendering that does
not distinguish the action they are approving from a different one, the
exact-digest binding holds and the approval still means nothing. Every decision
therefore carries a `summary`: a deterministic rendering derived from the same
structure the digest is computed over, so the text a human reads cannot drift
from the bytes they authorise.

Three properties are enforced by `tests/test_approval_surface_properties.py`,
which tests them over an adversarial corpus rather than over chosen examples:

- **Injective over the fields the digest covers — in the full rendering.**
  Every interpolated element is JSON-encoded — values, field names, tool and operation names, and source
  identifiers alike — and sources are rendered one per line with a count, so no
  field can borrow the layout's separators. Long values are abbreviated with
  the full SHA-256 and length appended. This is tested as a property over an
  adversarial corpus rather than over chosen examples; it is not a proof, and
  the 0.8.1 version of this claim was false (advisory MG-2026-002).
  This holds for the full rendering only. The `PreToolUse` adapter shows an
  elided rendering instead — values replaced by their length — because that
  channel is logged and sits beside the host's own display of the same call.
  The elided form is deliberately **not** injective: two different recipients
  of the same length read alike. It is a classification summary, not the thing
  being signed; that path carries no approval mechanism at all.
  Homoglyphs and bidirectional overrides remain legible to the renderer but not
  to a human reader: two visually identical identifiers with different digests
  will render differently, but a person may not see the difference.
- **Unforgeable from inside.** Values are JSON-encoded, which escapes newlines
  and control characters. An argument containing `\n  target : safe@example.com`
  is rendered as escaped text inside its value, not promoted to a field line.
- **Compound-disclosing.** When a request chains several effects — `&&`, `||`,
  `;`, `|`, `$(…)`, backticks, process substitution, `$'…'`, or embedded
  newlines — the summary says so. The scan covers `target` and recurses into
  nested lists and mappings, and the `PreToolUse` adapter forwards the markers
  it finds in the fields whose value is executed — `command`, `cmd`, `script`,
  `argv`, `args`, `shell` — at any nesting depth, so an argv array is covered
  too. Shell strings cannot be safely split into separate typed actions, so the
  boundary discloses compositeness instead of pretending to decompose it.

  Two exclusions are deliberate. A bare `&` is not a marker: it occurs in
  ordinary query strings, and a warning that fires on every parameterised URL
  would be trained away. Extraction is limited to executed fields because
  scanning every field fired on most ordinary calls — file content, edit
  replacements, and search patterns legitimately contain newlines and pipes. A
  warning that fires constantly is trained away, which is the same failure as
  not warning at all. A tool passing a command under some other key is
  therefore not disclosed as compound; such a tool is outside the declared set
  and reaches `ask` as `unknown`. Both directions of this choice are asserted
  in `tests/test_mediation_coverage.py`.

This narrows, but does not close, the granularity gap: one approval still
covers the whole compound command. The approver is told that, rather than left
to infer it.

## What may and may not be claimed

Permitted: *within the declared tool set, no effect-bearing call reaches the
agent without a gate decision, and unrecognised tools fail closed.*

Not permitted: complete prevention, mediation of all agent effects, or any
efficacy claim. The held-out evaluation has not met its predeclared floors, and
the prospective study remains unexecuted.
