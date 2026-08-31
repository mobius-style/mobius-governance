from __future__ import annotations

import contextlib
import io
import json
import tomllib
import unittest
from pathlib import Path

import mobius_governance
from mobius_governance.cli import main


ROOT = Path(__file__).resolve().parents[1]


class V07PackageSurfaceTests(unittest.TestCase):
    def test_module_and_distribution_metadata_are_v082(self) -> None:
        # The package version is 0.8.0 (action-gate security fix); the detector
        # engine is deliberately still structural_v0_7 because the scanner and
        # its 130-rule policy are unchanged by that fix.
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(mobius_governance.__version__, "0.8.2")
        self.assertEqual(project["project"]["version"], "0.8.2")

    def test_cli_manifest_defaults_to_v07_and_keeps_all_explicit_compatibility_modes(self) -> None:
        for arguments, expected in (
            (["manifest"], "structural_v0_7"),
            (["manifest", "--detector-mode", "structural_v0_4"], "structural_v0_4"),
            (["manifest", "--detector-mode", "structural_v0_5"], "structural_v0_5"),
            (["manifest", "--detector-mode", "structural_v0_6"], "structural_v0_6"),
        ):
            with self.subTest(arguments=arguments):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    status = main(arguments)
                self.assertEqual(status, 0)
                payload = json.loads(stream.getvalue())
                self.assertEqual(payload["detector"]["mode"], expected)

    def test_server_version_tracks_the_package(self) -> None:
        """A hard-coded version silently advertises a withdrawn release.

        Until 0.8.2 the HTTP app declared 0.7.0 -- the exact version withdrawn
        under advisory MG-2026-001 -- so an operator fingerprinting a patched
        server through /openapi.json saw the vulnerable one.
        """
        source = (ROOT / "src/mobius_governance/server.py").read_text(encoding="utf-8")
        self.assertIn("version=__version__", source)
        self.assertNotIn('version="0.', source)


if __name__ == "__main__":
    unittest.main()
