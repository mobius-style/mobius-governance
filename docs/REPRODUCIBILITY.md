# Reproducibility

From a fresh clone, use an explicit interpreter and keep the source tree clean:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps .
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -B \
  -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -B \
  tools/public_contract_suite.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B \
  tools/public_release_check.py --root . --verify-manifest --self-test
```

The receiver should additionally compare `PUBLIC_MANIFEST.json` with the actual
tree. A clean result means the declared public artifact is intact; it does not
mean the detector is universally effective.

