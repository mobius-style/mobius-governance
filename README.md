# mobius-governance

`mobius-governance` 0.8.0 is a local-first, model-independent alpha for
bounded retrieval-context scanning and typed agent-action mediation.

Current evidence status: **implementation verified; efficacy NOT ESTABLISHED**.
This release is a prototype and is not complete prompt-injection prevention,
a certification, a production deployment recommendation, or field-performance
evidence.

## What it provides

- deterministic English/Japanese context scanning with observable policy
  identity, rule count, profile, and resolved path;
- strict fail-closed policy loading and bounded context processing;
- typed `allow` / `ask` / `deny` action decisions bound to an exact action
  digest;
- a Claude Code `PreToolUse` adapter that never echoes raw tool input;
- a small OpenAI-compatible proxy surface;
- a standard-library core and reproducible public contract tests.

Context admission never authorizes a side effect. The scanner, `ActionGate`,
host-agent permissions, and operating-system sandbox are separate layers.

## Install locally

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps .
.venv/bin/python -m mobius_governance.cli manifest --detector-mode structural_v0_7
.venv/bin/python -m mobius_governance.cli selfcheck --detector-mode structural_v0_7
```

The core package has no mandatory third-party dependency. The optional HTTP
surface uses the `serve` extra. The optional RCGov integration is installed
separately and remains under its own license.

## Verify this snapshot

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B \
  tools/public_contract_suite.py
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  tools/public_release_check.py --root . --verify-manifest --self-test
```

The public contract suite is a transparent, deterministic regression suite. It
is not an independent benchmark and must not be cited as product efficacy.

## Evidence boundary

- The receiver-verified internal candidate wheel has SHA-256
  `d9fc7c630a777413db6d13b3ec1936d74d91da035f529e71e9a56492ee938506`.
- Runtime source/data files in this snapshot are byte-identical to that
  candidate's source members; verify the release manifest rather than trusting
  this statement.
- Historical development aggregates and failed/invalid evaluation corpora are
  deliberately excluded.
- Protected N800 has not run, protected outcomes have not been opened, and no
  paper efficacy data is included.

See [Evidence and limitations](docs/EVIDENCE_AND_LIMITATIONS.md),
[Research status](docs/RESEARCH_STATUS.md), and [Security policy](SECURITY.md).

## Security model

The package is a defense-in-depth component, not a hostile-process boundary.
It does not make arbitrary untrusted Python safe inside the same interpreter,
and it does not replace least-privilege credentials, human approval, sandboxing,
logging, or rollback. Missing required policy state fails closed.

Do not place historical MOBIUS/Elsa corpora or L0/TVS/MKR/KVS/muQK prompt
material into a running adapter's system prompt. Those materials are not
runtime inputs to this release.

## What is mediated, and what is not

The action gate mediates a declared set of eleven `PreToolUse` tools; anything
outside that set fails closed. The interior of a `Bash` command is explicitly
**not** mediated — it is gated as one opaque action, never admitted without
approval, but the gate cannot see what the shell string will do. The full
boundary, including the effect paths that never reach the adapter at all, is in
[`docs/MEDIATION_SCOPE.md`](docs/MEDIATION_SCOPE.md) and is enforced by
`tests/test_mediation_coverage.py`, which derives the declared set from the
classifier source so prose and code cannot drift apart.

## Reproducible checks under `eval/`

`eval/injection_corpus.py` and `eval/router_corpus.py` are small hand-written
smoke corpora that run against this tree. They are regression checks, not
efficacy measurements — see `docs/EVIDENCE_AND_LIMITATIONS.md` for the
held-out evaluation and the predeclared floors it did not meet.

## In the MOBIUS program

- [infinity](https://github.com/mobius-style/infinity) — MMV **× RQA** composite (adds the reflective-questioning tier this repo omits)
- [rcgov](https://github.com/mobius-style/rcgov) — the context governor · [paper (Zenodo 10.5281/zenodo.21231386)](https://doi.org/10.5281/zenodo.21231386)
- **Transformers-local instantiation**: [`moebiusT7/gemma-4-12b-mobius-custom`](https://huggingface.co/moebiusT7/gemma-4-12b-mobius-custom) — Gemma 4 12B (NF4) with an earlier revision of this governance layer baked in as `trust_remote_code`.
- **Companion paper** — *Governance Before Generation*, Zenodo, DOI [10.5281/zenodo.21357562](https://doi.org/10.5281/zenodo.21357562): an earlier N=100 A/B. It does not cover this release; see `docs/EVIDENCE_AND_LIMITATIONS.md`.
- **Preregistration paper** — *Preregistration as an Executable Contract*, Zenodo, DOI [10.5281/zenodo.22138712](https://doi.org/10.5281/zenodo.22138712): the frozen design, endpoints, and analysis plan of the prospective paired N=800 evaluation of this assurance plane. No outcome data exist; the study is HOLD_NOT_EXECUTABLE.
- **Foundations paper** — *Empty Text, Normed Acts*, Zenodo, DOI [10.5281/zenodo.22139691](https://doi.org/10.5281/zenodo.22139691): the reverse-derived theory behind the design — why enumeration loses, why reified guards fail silently, and why judgment attaches to the typed act. No efficacy claims.

## Practical kits

The operational discipline behind this project — abstain gates, kill switches,
regression evals, rollback — is available as a practical audit kit for small
teams: [free 25-point checklist](https://toeda.gumroad.com/l/free-checklist) ·
[full kit + monthly safety briefing](https://toeda.gumroad.com/l/safety-briefing).

## License

**AGPL-3.0-or-later**, © 2026 MOBIUS.LLC / Taiko Toeda.

### Commercial license

If your organization cannot meet AGPL's source-disclosure obligations, a
commercial license is available from MOBIUS LLC (sole rights holder):
**USD 500 per month, per company — cancel anytime, no minimum term.**
Annual invoicing available at USD 5,000/year.

It is a license grant, not a service: no service is performed, no data of
yours is accessed, and nothing you run depends on our availability.

Contact: **info@mobius.style** — licensing questions are not handled in Issues.

