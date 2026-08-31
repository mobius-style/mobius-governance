# mobius-governance 0.8.0-alpha

This release fixes a security defect in the action gate and is a breaking
change to the approval schema. See `SECURITY.md` (advisory MG-2026-001) and
`CHANGELOG.md`. In 0.7.0 an approval bound only the action digest, which
identifies an action class rather than one execution, so a single grant
re-authorised every later identical action. Approvals now carry a nonce, an
audience, and an expiry, and promotion requires a consumption ledger.

The package remains a history-free public implementation snapshot of the V13+
bounded context scanner and action mediator.

The release is intentionally narrow: runtime source, default policy, public
contract tests, reproducibility instructions, and licensing. Historical
holdouts, private evaluation artifacts, protected N800 materials, and prior Git
history are excluded.

Evidence status: implementation verified; efficacy not established. This
release does not claim complete prompt-injection prevention, certification,
production deployment readiness, peer review, or protected N800 results.

