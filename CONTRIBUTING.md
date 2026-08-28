# Contributing

Contributions are welcome when they preserve the package's bounded claims and
fail-closed behavior.

Before submitting a change:

1. add a known-broken case that fails before the fix;
2. add or retain a known-good hard negative;
3. run the complete public test and contract suites;
4. report policy/rule-count changes and any changed decision boundary;
5. do not include private prompts, credentials, customer data, historical
   holdouts, or protected N800 material.

Changes to prompts, policy rules, routing, or action mediation are eval-gated.
A passing unit test is implementation evidence, not efficacy evidence.

