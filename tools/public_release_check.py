#!/usr/bin/env python3
"""Close and verify the public snapshot without trusting Git history."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any


MANIFEST_NAME = "PUBLIC_MANIFEST.json"
SIDECAR_NAME = "PUBLIC_MANIFEST.sha256"
CORE_TOP_LEVEL = {
    ".gitignore",
    "eval",
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "RELEASE_NOTES.md",
    "SECURITY.md",
    "docs",
    "pyproject.toml",
    "src",
    "tests",
    "tools",
}
OPTIONAL_TOP_LEVEL = {MANIFEST_NAME, SIDECAR_NAME}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "build", "dist"}
TEXT_EXEMPT_MARKERS = (
    b"FAKE",
    b"EXAMPLE",
    b"REDACTED",
    b"TEST",
    b"SENTINEL",
    b"MUST_NOT_LEAK",
)
SECRET_PATTERNS = (
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(rb"sk-[A-Za-z0-9]{20,}"),
    re.compile(rb"AKIA[A-Z0-9]{16}"),
    re.compile(rb"AIza[A-Za-z0-9_-]{30,}"),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
ASSIGNMENT = re.compile(
    rb"(?i)(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{20,})"
)
LOCAL_PATTERNS = (
    re.compile(rb"/home/[A-Za-z0-9_.-]+/"),
    re.compile(rb"[A-Za-z]:\\Users\\[^\\]+\\"),
    re.compile(rb"\.codex(?:/|\\)"),
    re.compile(rb"\.claude(?:/|\\)"),
)


class ReleaseCheckError(RuntimeError):
    pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _scan_bytes(relative: str, raw: bytes) -> list[str]:
    findings: list[str] = []
    lowered_path = relative.lower()
    if any(term in Path(lowered_path).name for term in ("holdout", "quarantine", "credential", ".env")):
        findings.append(f"forbidden filename:{relative}")
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            value = match.group(0).upper()
            if not any(marker in value for marker in TEXT_EXEMPT_MARKERS):
                findings.append(f"secret signature:{relative}")
    for match in ASSIGNMENT.finditer(raw):
        value = match.group(1).upper()
        if not any(marker in value for marker in TEXT_EXEMPT_MARKERS):
            findings.append(f"credential assignment:{relative}")
    for pattern in LOCAL_PATTERNS:
        if pattern.search(raw):
            findings.append(f"local identifier:{relative}")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(f"non-UTF-8 file:{relative}")
    return findings


def _walk(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRS)
        for name in list(directories):
            path = current_path / name
            if path.is_symlink():
                raise ReleaseCheckError(f"symlink directory forbidden:{path.relative_to(root)}")
            records.append({"kind": "directory", "path": path.relative_to(root).as_posix()})
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if relative in {MANIFEST_NAME, SIDECAR_NAME}:
                continue
            if path.is_symlink() or not path.is_file():
                raise ReleaseCheckError(f"non-regular file forbidden:{relative}")
            raw = path.read_bytes()
            records.append(
                {"kind": "file", "path": relative, "sha256": _sha256(raw), "size": len(raw)}
            )
    return sorted(records, key=lambda item: item["path"])


def scan_tree(root: Path) -> dict[str, Any]:
    actual_top = {path.name for path in root.iterdir() if path.name != ".git"}
    if not CORE_TOP_LEVEL.issubset(actual_top):
        raise ReleaseCheckError(f"missing top-level entries:{sorted(CORE_TOP_LEVEL - actual_top)}")
    if actual_top - CORE_TOP_LEVEL - OPTIONAL_TOP_LEVEL:
        raise ReleaseCheckError(
            f"undeclared top-level entries:{sorted(actual_top - CORE_TOP_LEVEL - OPTIONAL_TOP_LEVEL)}"
        )
    records = _walk(root)
    findings: list[str] = []
    for record in records:
        if record["kind"] != "file":
            continue
        findings.extend(_scan_bytes(record["path"], (root / record["path"]).read_bytes()))
    readme = (root / "README.md").read_text(encoding="utf-8")
    for required in (
        "efficacy NOT ESTABLISHED",
        "not complete prompt-injection prevention",
        "Protected N800 has not run",
    ):
        if required not in readme:
            findings.append(f"required claim boundary absent:{required}")
    if findings:
        raise ReleaseCheckError(";".join(findings))
    return {
        "schema_version": "mobius.public-release-scan.v1",
        "status": "PASS",
        "record_count": len(records),
        "file_count": sum(item["kind"] == "file" for item in records),
        "directory_count": sum(item["kind"] == "directory" for item in records),
        "secret_findings": 0,
        "local_identifier_findings": 0,
        "protected_data_files": 0,
        "efficacy_claims_authorized": False,
    }


def write_manifest(root: Path) -> dict[str, Any]:
    scan = scan_tree(root)
    manifest_path = root / MANIFEST_NAME
    sidecar_path = root / SIDECAR_NAME
    if manifest_path.exists() or sidecar_path.exists():
        raise ReleaseCheckError("public manifest is first-write; existing files cannot be overwritten")
    document = {
        "schema_version": "mobius.public-artifact-manifest.v1",
        "records": _walk(root),
    }
    raw = _canonical(document)
    digest = _sha256(raw)
    manifest_path.write_bytes(raw)
    sidecar_path.write_text(f"{digest}  {MANIFEST_NAME}\n", encoding="utf-8")
    return {**scan, "manifest_sha256": digest}


def verify_manifest(root: Path) -> dict[str, Any]:
    scan = scan_tree(root)
    manifest_path = root / MANIFEST_NAME
    sidecar_path = root / SIDECAR_NAME
    raw = manifest_path.read_bytes()
    document = json.loads(raw)
    if _canonical(document) != raw:
        raise ReleaseCheckError("manifest is not canonical JSON")
    if set(document) != {"schema_version", "records"}:
        raise ReleaseCheckError("manifest top-level schema mismatch")
    if document["schema_version"] != "mobius.public-artifact-manifest.v1":
        raise ReleaseCheckError("manifest version mismatch")
    if document["records"] != _walk(root):
        raise ReleaseCheckError("manifest records differ from actual tree")
    digest = _sha256(raw)
    if sidecar_path.read_text(encoding="utf-8") != f"{digest}  {MANIFEST_NAME}\n":
        raise ReleaseCheckError("manifest sidecar mismatch")
    return {**scan, "manifest_sha256": digest}


def self_test() -> dict[str, Any]:
    good = _scan_bytes("fixture.txt", b"bounded public example")
    bad_secret = _scan_bytes("fixture.txt", b"token=" + b"gh" + b"p_" + b"A" * 32)
    bad_local = _scan_bytes("fixture.txt", b"/" + b"home/example/private.txt")
    if good or not bad_secret or not bad_local:
        raise ReleaseCheckError("release scanner self-test failed")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "candidate.env"
        path.write_text("safe", encoding="utf-8")
        if not _scan_bytes(path.name, path.read_bytes()):
            raise ReleaseCheckError("filename scanner self-test failed")
    return {"known_good_passed": 1, "known_broken_passed": 3}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--verify-manifest", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if args.write_manifest == args.verify_manifest:
        parser.error("choose exactly one of --write-manifest or --verify-manifest")
    result = write_manifest(root) if args.write_manifest else verify_manifest(root)
    if args.self_test:
        result["scanner_calibration"] = self_test()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
