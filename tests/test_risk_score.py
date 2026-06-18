import unittest

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from linux_auditor import calculate_risk_score, calculate_overall_risk_level


class TestRiskScore(unittest.TestCase):
    def test_low_risk_score(self):
        checks = [
            {"status": "PASS", "severity": "Low"},
            {"status": "SKIPPED", "severity": "Info"},
        ]

        self.assertEqual(calculate_risk_score(checks), 0)
        self.assertEqual(calculate_overall_risk_level(0), "Low")

    def test_medium_risk_score(self):
        checks = [
            {"status": "FAIL", "severity": "Medium"},
            {"status": "INFO", "severity": "Low"},
        ]

        self.assertEqual(calculate_risk_score(checks), 7)
        self.assertEqual(calculate_overall_risk_level(8), "Medium")

    def test_high_risk_score(self):
        checks = [
            {"status": "FAIL", "severity": "High"},
            {"status": "FAIL", "severity": "High"},
        ]

        self.assertEqual(calculate_risk_score(checks), 20)
        self.assertEqual(calculate_overall_risk_level(20), "High")


if __name__ == "__main__":
    unittest.main()
