# mobius-governance 0.8.4-alpha

This release fixes one defect in how retrieved context reached the model, and
closes one gap in the built-in guard. See `SECURITY.md`, advisory MG-2026-004.

- **A secret on a `#` line survived.** When a segment of retrieved context was
  excised, 0.8.3 kept its first line if it looked like a heading. A commented
  line such as `# HF_TOKEN=…` looks like one, so the secret that caused the
  excision was handed to the model above the placeholder and repeated in
  `governed["excluded"][].heading`.
- **The built-in guard had no rule for AWS secret access keys.** It has one
  now (policy `2026-09-29.1`).

What changed for you:

- Install rcgov 0.2.2: `pip install "mobius-governance[govern]"` pins it. With
  an older rcgov, 0.8.4 behaves as if rcgov were not installed and says so
  (`rcgov_status="unavailable"`, or fail-closed under `require_rcgov=True`).
- The policy hash changed. If you pin it, re-pin after your own regression run.
- Decisions stored by 0.8.3 may hold a secret in
  `governed["excluded"][].heading`.

What did not change: the API, the shape of the metadata, the guard's other
rules. What is still not covered is listed in the advisory.
