# Evidence and limitations

## Current claim

The v0.7 package is a bounded alpha implementation whose package identity,
source members, policy custody, calibration behavior, and typed action boundary
were verified internally in isolated processes.

Permitted wording: **implementation candidate**, **alpha**, **defense in
depth**, and **efficacy not established**.

Not permitted: complete prevention, certification, production safety,
field-performance, peer-review, or protected N800 efficacy claims.

## Included evidence

- exact runtime source and default policy;
- public unit tests and deterministic contract regressions;
- an artifact manifest that closes the public tree;
- a reproducible source build path.

## Excluded evidence and data

- all historical holdout rows, labels, predictions, and raw outcomes;
- failed or invalid v5-v12 evaluation corpora and quarantine material;
- the internal 1,720-row development aggregate;
- the prospective protected N800 corpus and outcome data;
- Stage5 materials and authorizations;
- MOBIUS/Elsa historical corpora and runtime prompt material.

The exclusions prevent maturity levels from being conflated and reduce privacy,
contamination, and secret-history risk. Their absence also means this snapshot
does not independently establish efficacy.

## Known limitations

- Rule-based and structural detection has false negatives and false positives.
- Local calibration and public contract tests are development evidence.
- Same-process arbitrary Python is outside the security boundary.
- The component cannot replace credential isolation, tool permissions, human
  approval, sandboxing, monitoring, or rollback.
- Default policy behavior is bilingual but has not been established as robust
  across real-world languages, domains, encodings, or adversaries.

## Candidate anchor

The receiver-verified internal wheel identity is:

```text
mobius_governance-0.7.0-py3-none-any.whl
SHA-256 d9fc7c630a777413db6d13b3ec1936d74d91da035f529e71e9a56492ee938506
```

The release manifest proves the public source tree; it does not convert the
internal candidate identity into an efficacy result.

