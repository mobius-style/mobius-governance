# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""CLI: serve the governance proxy, or preflight a backend.

    mobius-governance serve --backend-url http://127.0.0.1:11434/v1 --model gemma4:12b
    mobius-governance preflight --backend-url http://127.0.0.1:11434/v1 --model gemma4:12b
"""
from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mobius-governance",
                                description="MMV + RCGov governance proxy (no RQA).")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend-url", default="http://127.0.0.1:11434/v1",
                        help="OpenAI-compatible backend (Ollama/vLLM/...).")
    common.add_argument("--model", default="gemma4:12b")
    common.add_argument("--api-key", default=None)
    common.add_argument("--rcgov-profile", default="Balanced",
                        choices=["Conservative", "Balanced", "Aggressive", "Research"])

    s = sub.add_parser("serve", parents=[common], help="Run the OpenAI-compatible API.")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    sub.add_parser("preflight", parents=[common], help="Check the backend is reachable.")

    args = p.parse_args(argv)
    from .backends import OpenAICompatBackend, BackendError
    backend = OpenAICompatBackend(base_url=args.backend_url, model=args.model,
                                  api_key=args.api_key)

    if args.cmd == "preflight":
        try:
            out = backend.chat("Reply with the single word: ok.", max_tokens=8)
            print(f"backend OK ({backend.base_url}, {backend.model}): {out[:60]!r}")
            return 0
        except BackendError as e:
            print(f"backend FAILED: {e}", file=sys.stderr)
            return 1

    if args.cmd == "serve":
        try:
            import uvicorn
        except ImportError:
            print("serving needs the 'serve' extra: pip install 'mobius-governance[serve]'",
                  file=sys.stderr)
            return 1
        from .core import GovernanceComposer
        from .server import create_app
        app = create_app(GovernanceComposer(rcgov_profile=args.rcgov_profile), backend)
        print(f"mobius-governance -> {args.backend_url} ({args.model}) "
              f"serving http://{args.host}:{args.port}/v1")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
