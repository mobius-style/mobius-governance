# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""CLI for policy inspection, calibration, scanning, action gating, and proxying.

    mobius-governance serve --backend-url http://127.0.0.1:11434/v1 --model gemma4:12b
    mobius-governance preflight --backend-url http://127.0.0.1:11434/v1 --model gemma4:12b
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _read_bytes(path: str) -> bytes:
    return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()


def _print_json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mobius-governance",
                                description="Bounded context and action governance MVP.")
    sub = p.add_subparsers(dest="cmd", required=True)

    policy_common = argparse.ArgumentParser(add_help=False)
    policy_common.add_argument("--policy", default=None,
                               help="Strict JSON guard policy (packaged default when omitted).")
    policy_common.add_argument(
        "--detector-mode", default="structural_v0_7",
        choices=["legacy_v0_2", "structural_v0_3", "structural_v0_4", "structural_v0_5", "structural_v0_6", "structural_v0_7"],
        help="Host-selected detector mode; request payloads cannot override it.",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--backend-url", default="http://127.0.0.1:11434/v1",
                        help="OpenAI-compatible backend (Ollama/vLLM/...).")
    common.add_argument("--model", default="gemma4:12b")
    common.add_argument("--api-key", default=None)
    common.add_argument("--rcgov-profile", default="Balanced",
                        choices=["Conservative", "Balanced", "Aggressive", "Research"])
    common.add_argument("--policy", default=None)
    common.add_argument(
        "--detector-mode", default="structural_v0_7",
        choices=["legacy_v0_2", "structural_v0_3", "structural_v0_4", "structural_v0_5", "structural_v0_6", "structural_v0_7"],
    )

    s = sub.add_parser("serve", parents=[common], help="Run the OpenAI-compatible API.")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--require-rcgov", action="store_true",
                   help="Fail closed unless the optional RCGov layer is available.")

    sub.add_parser("preflight", parents=[common], help="Check the backend is reachable.")
    sub.add_parser("manifest", parents=[policy_common], help="Print the active policy manifest.")
    sub.add_parser("selfcheck", parents=[policy_common], help="Run known-bad/known-good calibration.")
    scan = sub.add_parser("scan", parents=[policy_common], help="Scan one UTF-8 context file; use - for stdin.")
    scan.add_argument("path")
    scan.add_argument("--source-id", default="cli")
    scan.add_argument("--trust", default="untrusted", choices=["trusted", "untrusted", "unknown"])
    action = sub.add_parser("action", parents=[policy_common], help="Decide a typed action request JSON file.")
    action.add_argument("request")
    action.add_argument("--approval", default=None,
                        help="Optional trusted approval JSON bound to the action digest.")
    sub.add_parser(
        "claude-hook",
        parents=[policy_common],
        help="Read a Claude Code PreToolUse JSON event from stdin and emit a decision.",
    )

    args = p.parse_args(argv)
    from .actions import ActionGate, ActionRequest, Approval
    from .policy import GuardEngine, PolicyError, load_json_object

    if args.cmd == "claude-hook":
        from .claude_hook import evaluate_claude_hook, fail_closed_hook_output
        try:
            engine = GuardEngine.from_path(args.policy, mode=args.detector_mode)
            payload = load_json_object(sys.stdin.buffer.read(), label="Claude hook input")
            _print_json(evaluate_claude_hook(payload, engine))
        except (OSError, PolicyError, TypeError) as exc:
            _print_json(fail_closed_hook_output(type(exc).__name__.upper()))
        return 0

    try:
        engine = GuardEngine.from_path(args.policy, mode=args.detector_mode)
        if args.cmd == "manifest":
            _print_json({
                "schema_version": "mobius.active-guard-manifest.v1",
                "policy": engine.manifest.to_dict(),
                "detector": engine.detector,
            })
            return 0
        if args.cmd == "selfcheck":
            result = engine.self_check()
            _print_json(result)
            return 0 if result["status"] == "PASS" else 1
        if args.cmd == "scan":
            text = _read_bytes(args.path).decode("utf-8")
            decision = engine.scan(text, source_id=args.source_id, trust=args.trust)
            _print_json({
                "schema_version": "mobius.context-scan.v1",
                "status": "PASS" if decision.decision == "admit" else "FILTERED",
                "policy": engine.manifest.to_dict(),
                "detector": engine.detector,
                "segments": [decision.to_dict()],
            })
            return 0 if decision.decision == "admit" else 1
        if args.cmd == "action":
            request = ActionRequest.from_dict(
                load_json_object(_read_bytes(args.request), label="action request")
            )
            approval = None
            if args.approval:
                approval = Approval.from_dict(
                    load_json_object(_read_bytes(args.approval), label="action approval")
                )
            # Supplying --approval is an explicit local-operator boundary.  The
            # public HTTP endpoint never enables this verifier from request JSON.
            verifier = (lambda supplied, action: True) if approval is not None else None
            decision = ActionGate(engine, approval_verifier=verifier).decide(request, approval)
            _print_json(decision.to_dict())
            return 0 if decision.decision == "allow" else 1
    except (OSError, UnicodeDecodeError, PolicyError, TypeError) as exc:
        print(f"governance FAILED: {exc}", file=sys.stderr)
        return 2

    from .backends import OpenAICompatBackend, BackendError
    backend = OpenAICompatBackend(base_url=args.backend_url, model=args.model,
                                  api_key=args.api_key)

    if args.cmd == "preflight":
        try:
            calibration = engine.self_check()
            if calibration["status"] != "PASS":
                _print_json(calibration)
                return 1
            out = backend.chat("Reply with the single word: ok.", max_tokens=8)
            print(f"policy OK ({engine.manifest.active_rule_count} active rules, "
                  f"{engine.manifest.sha256}); backend OK "
                  f"({backend.base_url}, {backend.model}): {out[:60]!r}")
            return 0
        except (BackendError, PolicyError) as e:
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
        calibration = engine.self_check()
        if calibration["status"] != "PASS":
            _print_json(calibration)
            return 1
        app = create_app(
            GovernanceComposer(
                rcgov_profile=args.rcgov_profile,
                guard_engine=engine,
                require_rcgov=args.require_rcgov,
            ),
            backend,
        )
        print(f"mobius-governance -> {args.backend_url} ({args.model}) "
              f"serving http://{args.host}:{args.port}/v1")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
