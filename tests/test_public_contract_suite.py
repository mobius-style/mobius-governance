from __future__ import annotations

import unittest

from tools.public_contract_suite import run_suite


class PublicContractSuiteTests(unittest.TestCase):
    def test_public_contract_regression_has_at_least_100_cases(self) -> None:
        result = run_suite()
        self.assertEqual(result["status"], "PASS", result["failures"])
        self.assertGreaterEqual(result["case_count"], 100)
        self.assertEqual(result["failures"], [])
        self.assertFalse(result["protected_data_opened"])
        self.assertFalse(result["n800_count_consumed"])


if __name__ == "__main__":
    unittest.main()

