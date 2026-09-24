import unittest

from benchmarks.run_benchmark import run_case


class BenchmarkTests(unittest.TestCase):
    def test_safe_fixture_has_no_expected_findings(self):
        result = run_case("safe", 1)
        self.assertEqual(result["expected_rule_recall"], 1.0)
        self.assertEqual(result["unexpected_rule_count"], 0)

    def test_vulnerable_fixture_detects_expected_rules(self):
        result = run_case("vulnerable", 1)
        self.assertEqual(result["missing_expected_rules"], [])
        self.assertEqual(result["unexpected_rule_count"], 0)
        self.assertGreater(result["files_analyzed"], 0)


if __name__ == "__main__":
    unittest.main()
