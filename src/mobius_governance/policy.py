# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""Deterministic context policy, active-control manifest, and calibration.

The policy is deliberately data-backed.  A missing, malformed, or unexpectedly
empty policy is an observable error and cannot silently become a clean result.
Raw context is never copied into a scan report; reports retain hashes and rule
identifiers only.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .structural import analyze as structural_analyze
from .structural import active_lexical_scopes
from .structural import detector_manifest


POLICY_SCHEMA = "mobius.guard-policy.v1"
REPORT_SCHEMA = "mobius.context-scan.v3"
DETECTOR_MODES = {
    "legacy_v0_2", "structural_v0_3", "structural_v0_4",
    "structural_v0_5", "structural_v0_6", "structural_v0_7",
}
MAX_CONTEXT_SEGMENTS = 1024
MAX_TOTAL_CONTEXT_BYTES = 8_000_000
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
_SPACE = re.compile(r"\s+")
_TOP_LEVEL_KEYS = {
    "schema_version", "policy_id", "version", "profile",
    "injection_threshold", "injection_rules", "secret_rules",
    "action_rules", "calibration",
}
_RULE_KEYS = {"id", "category", "weight", "pattern"}
_ACTIONS = {"allow", "ask", "deny"}


class PolicyError(ValueError):
    """The configured guard policy is absent, malformed, or uncalibrated."""


def _reject_constant(value: str) -> None:
    raise PolicyError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a JSON object")
    return value


def load_json_object(raw: bytes, *, label: str = "JSON document") -> dict[str, Any]:
    """Public strict-object loader shared by file-oriented adapters."""

    return _load_strict_json(raw, label=label)


def default_policy_path() -> Path:
    """Return the packaged default policy path without pretending it exists."""

    return Path(__file__).resolve().parent / "data" / "default_policy.json"


def normalize_text(text: str) -> tuple[str, bool]:
    """Normalize common visual obfuscation while reporting that it occurred."""

    raw = str(text or "")
    normalized = html.unescape(unicodedata.normalize("NFKC", raw))
    without_zero_width = _ZERO_WIDTH.sub("", normalized)
    changed = without_zero_width != raw
    return _SPACE.sub(" ", without_zero_width).strip().casefold(), changed


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: int
    pattern: str
    compiled: re.Pattern[str]


@dataclass(frozen=True)
class PolicyManifest:
    schema_version: str
    policy_id: str
    version: str
    profile: str
    resolved_path: str
    sha256: str
    active_rule_count: int
    injection_rule_count: int
    secret_rule_count: int
    action_rule_count: int
    fallback: bool
    status: str
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "version": self.version,
            "profile": self.profile,
            "resolved_path": self.resolved_path,
            "sha256": self.sha256,
            "active_rule_count": self.active_rule_count,
            "injection_rule_count": self.injection_rule_count,
            "secret_rule_count": self.secret_rule_count,
            "action_rule_count": self.action_rule_count,
            "fallback": self.fallback,
            "status": self.status,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ScanHit:
    rule_id: str
    category: str
    weight: int

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "category": self.category, "weight": self.weight}


@dataclass(frozen=True)
class SegmentDecision:
    source_id: str
    trust: str
    content_sha256: str
    byte_length: int
    decision: str
    risk_score: int
    normalized: bool
    hits: tuple[ScanHit, ...]
    detector_mode: str
    lexical_score: int
    structural_score: int
    evidence_ids: tuple[str, ...]
    analysis_units: int
    pass_count: int
    stop_reason: str
    witness_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id_sha256": hashlib.sha256(self.source_id.encode("utf-8")).hexdigest(),
            "trust": self.trust,
            "content_sha256": self.content_sha256,
            "byte_length": self.byte_length,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "normalized": self.normalized,
            "hits": [hit.to_dict() for hit in self.hits],
            "detector_mode": self.detector_mode,
            "lexical_score": self.lexical_score,
            "structural_score": self.structural_score,
            "evidence_ids": list(self.evidence_ids),
            "analysis_units": self.analysis_units,
            "pass_count": self.pass_count,
            "stop_reason": self.stop_reason,
            "witness_sha256": self.witness_sha256,
        }


@dataclass(frozen=True)
class GuardPolicy:
    manifest: PolicyManifest
    injection_threshold: int
    injection_rules: tuple[Rule, ...]
    secret_rules: tuple[Rule, ...]
    action_rules: Mapping[str, str]
    calibration: Mapping[str, Any]


def _compile_rules(value: Any, *, label: str) -> tuple[Rule, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{label} must be a non-empty array")
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != _RULE_KEYS:
            raise PolicyError(f"{label}[{index}] must contain exactly {sorted(_RULE_KEYS)}")
        identifier = item["id"]
        category = item["category"]
        pattern = item["pattern"]
        weight = item["weight"]
        if not all(isinstance(part, str) and part.strip() for part in (identifier, category, pattern)):
            raise PolicyError(f"{label}[{index}] has an empty id, category, or pattern")
        if identifier in seen:
            raise PolicyError(f"duplicate rule id: {identifier}")
        if (
            not isinstance(weight, int)
            or isinstance(weight, bool)
            or weight == 0
            or not -100 <= weight <= 100
        ):
            raise PolicyError(
                f"{label}[{index}].weight must be a non-zero integer from -100 to 100"
            )
        if len(pattern) > 2000:
            raise PolicyError(f"{label}[{index}].pattern is too large")
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            raise PolicyError(f"{label}[{index}] regex is invalid: {exc}") from exc
        seen.add(identifier)
        rules.append(Rule(identifier, category, weight, pattern, compiled))
    return tuple(rules)


def load_policy(path: str | Path | None = None) -> GuardPolicy:
    resolved = Path(path).expanduser().resolve(strict=False) if path else default_policy_path()
    if not resolved.is_file() or resolved.is_symlink():
        raise PolicyError(f"guard policy is not a readable regular file: {resolved}")
    raw = resolved.read_bytes()
    document = _load_strict_json(raw, label="guard policy")
    if set(document) != _TOP_LEVEL_KEYS:
        missing = sorted(_TOP_LEVEL_KEYS - set(document))
        extra = sorted(set(document) - _TOP_LEVEL_KEYS)
        raise PolicyError(f"guard policy keys mismatch; missing={missing}, extra={extra}")
    if document["schema_version"] != POLICY_SCHEMA:
        raise PolicyError(f"unsupported guard policy schema: {document['schema_version']!r}")
    for key in ("policy_id", "version", "profile"):
        if not isinstance(document[key], str) or not document[key].strip():
            raise PolicyError(f"guard policy {key} must be a non-empty string")
    threshold = document["injection_threshold"]
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not 1 <= threshold <= 100:
        raise PolicyError("injection_threshold must be an integer from 1 to 100")
    injections = _compile_rules(document["injection_rules"], label="injection_rules")
    secrets = _compile_rules(document["secret_rules"], label="secret_rules")
    actions = document["action_rules"]
    if not isinstance(actions, dict) or "unknown" not in actions:
        raise PolicyError("action_rules must be an object containing an unknown rule")
    for operation, decision in actions.items():
        if not isinstance(operation, str) or not operation.strip() or decision not in _ACTIONS:
            raise PolicyError(f"invalid action rule: {operation!r} -> {decision!r}")
    calibration = document["calibration"]
    if not isinstance(calibration, dict) or set(calibration) != {"known_bad", "known_good"}:
        raise PolicyError("calibration must contain exactly known_bad and known_good")
    digest = hashlib.sha256(raw).hexdigest()
    manifest = PolicyManifest(
        schema_version=POLICY_SCHEMA,
        policy_id=document["policy_id"],
        version=document["version"],
        profile=document["profile"],
        resolved_path=str(resolved),
        sha256=digest,
        active_rule_count=len(injections) + len(secrets) + len(actions),
        injection_rule_count=len(injections),
        secret_rule_count=len(secrets),
        action_rule_count=len(actions),
        fallback=False,
        status="active",
    )
    return GuardPolicy(manifest, threshold, injections, secrets, dict(actions), calibration)


class GuardEngine:
    """Bounded deterministic scanner with a receiver-verifiable policy manifest."""

    def __init__(self, policy: GuardPolicy, *, mode: str = "structural_v0_7") -> None:
        if mode not in DETECTOR_MODES:
            raise PolicyError(f"unsupported detector mode: {mode!r}")
        self.policy = policy
        self.mode = mode

    @classmethod
    def from_path(
        cls, path: str | Path | None = None, *, mode: str = "structural_v0_7"
    ) -> "GuardEngine":
        return cls(load_policy(path), mode=mode)

    @property
    def manifest(self) -> PolicyManifest:
        return self.policy.manifest

    @property
    def detector(self) -> dict[str, object]:
        return detector_manifest(self.mode)

    def _decision(
        self,
        *,
        source_id: str,
        trust: str,
        encoded: bytes,
        changed: bool,
        hits: list[ScanHit],
        lexical_score: int,
        structural_score: int,
        evidence_ids: tuple[str, ...],
        analysis_units: int,
        pass_count: int,
        stop_reason: str,
    ) -> SegmentDecision:
        secret = any(hit.category == "secret" for hit in hits)
        score = lexical_score if self.mode == "legacy_v0_2" else max(lexical_score, structural_score)
        decision = "drop" if secret or score >= self.policy.injection_threshold else "admit"
        content_sha256 = hashlib.sha256(encoded).hexdigest()
        witness_payload = {
            "content_sha256": content_sha256,
            "decision": decision,
            "detector": self.detector,
            "evidence_ids": list(evidence_ids),
            "lexical_score": lexical_score,
            "policy_sha256": self.manifest.sha256,
            "risk_score": score,
            "source_id": source_id,
            "stop_reason": stop_reason,
            "structural_score": structural_score,
            "trust": trust,
        }
        witness_sha256 = hashlib.sha256(
            json.dumps(witness_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return SegmentDecision(
            source_id=source_id,
            trust=trust,
            content_sha256=content_sha256,
            byte_length=len(encoded),
            decision=decision,
            risk_score=score,
            normalized=changed,
            hits=tuple(hits),
            detector_mode=self.mode,
            lexical_score=lexical_score,
            structural_score=structural_score,
            evidence_ids=evidence_ids,
            analysis_units=analysis_units,
            pass_count=pass_count,
            stop_reason=stop_reason,
            witness_sha256=witness_sha256,
        )

    def scan(self, text: str, *, source_id: str = "context", trust: str = "untrusted") -> SegmentDecision:
        if trust not in {"untrusted", "trusted", "unknown"}:
            raise PolicyError(f"unsupported trust label: {trust!r}")
        raw = str(text or "")
        encoded = raw.encode("utf-8")
        if len(encoded) > 2_000_000:
            raise PolicyError("context segment exceeds the 2,000,000-byte MVP limit")
        normalized, changed = normalize_text(raw)
        hits: list[ScanHit] = []
        for rule in self.policy.injection_rules + self.policy.secret_rules:
            if rule.compiled.search(normalized):
                hits.append(ScanHit(rule.id, rule.category, rule.weight))
        if self.mode == "legacy_v0_2":
            score = max(0, min(100, sum(hit.weight for hit in hits)))
            return self._decision(
                source_id=source_id,
                trust=trust,
                encoded=encoded,
                changed=changed,
                hits=hits,
                lexical_score=score,
                structural_score=0,
                evidence_ids=tuple(sorted(hit.rule_id for hit in hits)),
                analysis_units=1,
                pass_count=1,
                stop_reason="legacy_single_pass",
            )

        # Safe-scope evidence is local in the structural engine.  It is never a
        # negative global weight.  Exact high-risk signatures remain a first-stage
        # signal, while broad component rules are composed relationally in stage two.
        positive = [hit for hit in hits if hit.weight > 0 and hit.category != "secret"]
        direct_candidates = [
            hit for hit in positive
            if not hit.category.startswith("risk_component_") and hit.category != "safe_scope"
        ]
        scopes = active_lexical_scopes(normalized, self.mode)
        lexical_text = " ".join(scopes)
        rules_by_id = {rule.id: rule for rule in self.policy.injection_rules}
        direct = [
            hit for hit in direct_candidates
            if rules_by_id[hit.rule_id].compiled.search(lexical_text)
        ]
        component_rules = [
            rule for rule in self.policy.injection_rules
            if rule.category.startswith("risk_component_")
        ]

        def component_score(scope: str) -> tuple[int, set[str]]:
            by_category: dict[str, int] = {}
            identifiers: set[str] = set()
            for rule in component_rules:
                if scope and rule.compiled.search(scope):
                    by_category[rule.category] = max(by_category.get(rule.category, 0), rule.weight)
                    identifiers.add(rule.id)
            return min(100, sum(by_category.values())), identifiers

        component_candidates = [component_score(scope) for scope in scopes if scope]
        component_candidates.extend(
            component_score(f"{left} {right}")
            for left, right in zip(scopes, scopes[1:])
            if left and right
        )
        best_component_score = max((score for score, _ in component_candidates), default=0)
        active_component_ids = set().union(
            *(ids for score, ids in component_candidates if score == best_component_score)
        ) if component_candidates else set()
        lexical_score = max(max((hit.weight for hit in direct), default=0), best_component_score)
        structural = structural_analyze(normalized, self.mode)
        evidence_ids = tuple(sorted(
            set(structural.evidence_ids)
            | {f"lexical.{hit.rule_id}" for hit in direct}
            | {f"component.{identifier}" for identifier in active_component_ids}
        ))
        return self._decision(
            source_id=source_id,
            trust=trust,
            encoded=encoded,
            changed=changed,
            hits=hits,
            lexical_score=lexical_score,
            structural_score=structural.score,
            evidence_ids=evidence_ids,
            analysis_units=structural.analysis_units,
            pass_count=structural.pass_count,
            stop_reason=structural.stop_reason,
        )

    def scan_context(self, segments: Iterable[Any]) -> tuple[list[str], dict[str, Any]]:
        if isinstance(segments, (str, bytes, bytearray)):
            raise PolicyError("context segments must be an iterable of segments, not raw text")
        try:
            declared_count = len(segments)  # type: ignore[arg-type]
        except TypeError:
            declared_count = None
        if declared_count is not None and declared_count > MAX_CONTEXT_SEGMENTS:
            raise PolicyError(f"context exceeds the {MAX_CONTEXT_SEGMENTS}-segment MVP limit")
        admitted: list[str] = []
        decisions: list[SegmentDecision] = []
        total_context_bytes = 0
        for index, item in enumerate(segments):
            if index >= MAX_CONTEXT_SEGMENTS:
                raise PolicyError(f"context exceeds the {MAX_CONTEXT_SEGMENTS}-segment MVP limit")
            if isinstance(item, dict):
                if set(item) - {"source_id", "content", "trust"}:
                    raise PolicyError(f"context segment {index} contains unknown keys")
                content = str(item.get("content", ""))
                source_id = str(item.get("source_id", f"context_{index:03d}"))
                trust = str(item.get("trust", "untrusted"))
            else:
                content = str(item)
                source_id = f"context_{index:03d}"
                trust = "untrusted"
            if not source_id or len(source_id) > 200:
                raise PolicyError(f"context segment {index} has an invalid source_id")
            total_context_bytes += len(content.encode("utf-8"))
            if total_context_bytes > MAX_TOTAL_CONTEXT_BYTES:
                raise PolicyError(f"context exceeds the {MAX_TOTAL_CONTEXT_BYTES}-byte aggregate MVP limit")
            decision = self.scan(content, source_id=source_id, trust=trust)
            decisions.append(decision)
            if decision.decision == "admit":
                admitted.append(content)
        report = {
            "schema_version": REPORT_SCHEMA,
            "status": "PASS" if all(item.decision == "admit" for item in decisions) else "FILTERED",
            "admitted_count": len(admitted),
            "dropped_count": len(decisions) - len(admitted),
            "policy": self.manifest.to_dict(),
            "detector": self.detector,
            "segments": [item.to_dict() for item in decisions],
        }
        return admitted, report

    def self_check(self) -> dict[str, Any]:
        bad_failures: list[str] = []
        good_failures: list[str] = []
        known_bad = self.policy.calibration.get("known_bad")
        known_good = self.policy.calibration.get("known_good")
        if not isinstance(known_bad, list) or not known_bad:
            raise PolicyError("calibration.known_bad must be a non-empty array")
        if not isinstance(known_good, list) or not known_good:
            raise PolicyError("calibration.known_good must be a non-empty array")
        for case in known_bad:
            if not isinstance(case, dict) or set(case) != {"id", "text", "expect_rule"}:
                raise PolicyError("known_bad calibration case has an invalid shape")
            decision = self.scan(case["text"], source_id=case["id"])
            rule_ids = {hit.rule_id for hit in decision.hits}
            if decision.decision != "drop" or case["expect_rule"] not in rule_ids:
                bad_failures.append(case["id"])
        for case in known_good:
            if not isinstance(case, dict) or set(case) != {"id", "text"}:
                raise PolicyError("known_good calibration case has an invalid shape")
            decision = self.scan(case["text"], source_id=case["id"])
            if decision.decision != "admit":
                good_failures.append(case["id"])
        passed = not bad_failures and not good_failures
        return {
            "schema_version": "mobius.guard-calibration.v1",
            "status": "PASS" if passed else "FAIL",
            "known_bad": {"total": len(known_bad), "passed": len(known_bad) - len(bad_failures), "failures": bad_failures},
            "known_good": {"total": len(known_good), "passed": len(known_good) - len(good_failures), "failures": good_failures},
            "policy": self.manifest.to_dict(),
            "detector": self.detector,
        }


__all__ = [
    "GuardEngine", "GuardPolicy", "PolicyError", "PolicyManifest", "Rule",
    "ScanHit", "SegmentDecision", "default_policy_path", "load_policy",
    "load_json_object", "normalize_text", "DETECTOR_MODES", "MAX_CONTEXT_SEGMENTS",
    "MAX_TOTAL_CONTEXT_BYTES",
]
