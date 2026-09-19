# mobius-governance 0.8.3-alpha

This release fixes one defect in how retrieved context reached the model. See
`SECURITY.md`, advisory MG-2026-003.

- `govern_context()` returned rcgov's **Clean Context Pack** as the governed
  text. The pack is a *triage* of the input by authority and priority, not a
  scrubbed copy: a segment rcgov routed to review — typically an English
  paragraph of plain prose with no provenance — was omitted with no marker, so
  whenever any other segment was admitted that text vanished from the prompt
  while `governed=True` and `context_empty=False`. The model answered without
  it and nothing said so.
- Retrieved context is now rebuilt segment by segment from rcgov's records.
  Excluded segments (confirmed secrets, injection patterns, block/quarantine
  gates) leave a placeholder and are listed with their reason in
  `governed["excluded"]`; heuristic-only flags are kept and listed; the rest is
  byte-identical to what you passed in. `context_empty` follows
  `governed["admitted_segment_count"]`.
- Unchanged: the mandatory built-in guard, `require_rcgov` fail-closed
  semantics, and degraded mode when the optional rcgov fails.

The same defect shipped in three sibling artifacts (`gemma-4-12b-mobius-custom`
v1.0 and both `*-mobius-custom-c1` wrappers) and is fixed there too. It was
found by using the wrappers, not by review — the first day they ran as the
author's own session-record clerk. `rcgov` 0.2.0 adds `rebuild_bytes()` for
this use case.

Evidence status: implementation verified; **efficacy not established**. The
held-out evaluation did not meet its predeclared minimum floors, and the
prospective study remains unexecuted. This release does not claim complete
prompt-injection prevention, certification, or production readiness. The
interior of a `Bash` command is not mediated; see `docs/MEDIATION_SCOPE.md`.
