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
admitted. This covers MCP server tools, future first-party tools, plugins, and
near-misses of declared names, including case variations, trailing whitespace,
and Unicode homoglyphs. The tests probe each of these explicitly. Malformed
payloads and non-`PreToolUse` events raise rather than return a decision, so a
caller cannot obtain a permissive default by sending a broken request.

## Out of scope — stated, not assumed

**The interior of a `Bash` command.** `Bash` is mediated as one opaque action.
Its command string is inspected by pattern to raise the operation to `delete` or
`admin` where it can, and to mark network-reaching commands external, but a
shell string can express arbitrary effects and can be obfuscated without limit.
`echo <base64> | base64 -d | sh` classifies as a plain `execute`. It is still
gated — it reaches `ask`, never `allow` — but the gate cannot see what the shell
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

## What may and may not be claimed

Permitted: *within the declared tool set, no effect-bearing call reaches the
agent without a gate decision, and unrecognised tools fail closed.*

Not permitted: complete prevention, mediation of all agent effects, or any
efficacy claim. The held-out evaluation has not met its predeclared floors, and
the prospective study remains unexecuted.
