from __future__ import annotations

import unittest

from tools.public_release_check import _scan_bytes, self_test


class PublicReleaseCheckTests(unittest.TestCase):
    def test_scanner_is_calibrated_on_good_and_bad_examples(self) -> None:
        self.assertEqual(
            self_test(),
            {"known_good_passed": 1, "known_broken_passed": 3},
        )

    def test_fake_test_credentials_are_allowed_but_real_shapes_are_not(self) -> None:
        self.assertEqual(_scan_bytes("fixture.txt", b"api_key=FAKE_TEST_VALUE_123456789"), [])
        secret = b"api_key=" + b"Z" * 32
        self.assertTrue(_scan_bytes("fixture.txt", secret))


if __name__ == "__main__":
    unittest.main()

