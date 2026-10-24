
"""
Automated tests for SignalIQ vulnerability prioritization.

Tests priority classification, ranking order, missing values,
and database retrieval using temporary SQLite databases.
"""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from src.prioritization.priority_engine import (
    classify_vulnerability,
    rank_vulnerabilities,
)


class TestPriorityClassification(unittest.TestCase):
    """Verify the four SignalIQ priority tiers."""

    def test_p1_known_ransomware_use(self):
        result = classify_vulnerability(
            cvss_score=5.0,
            epss_score=0.05,
            known_ransomware_use="Known",
        )

        self.assertEqual(result["priority"], 1)
        self.assertIn(
            "CISA identifies known ransomware use",
            result["reasons"],
        )

    def test_p1_high_epss_and_critical_cvss(self):
        result = classify_vulnerability(
            cvss_score=9.8,
            epss_score=0.85,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 1)

    def test_p2_high_epss(self):
        result = classify_vulnerability(
            cvss_score=6.5,
            epss_score=0.80,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 2)

    def test_p2_combined_epss_and_cvss(self):
        result = classify_vulnerability(
            cvss_score=8.0,
            epss_score=0.45,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 2)

    def test_p3_elevated_epss(self):
        result = classify_vulnerability(
            cvss_score=5.0,
            epss_score=0.20,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 3)

    def test_p3_high_cvss(self):
        result = classify_vulnerability(
            cvss_score=8.0,
            epss_score=0.05,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 3)

    def test_p4_baseline_kev(self):
        result = classify_vulnerability(
            cvss_score=5.0,
            epss_score=0.02,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 4)

    def test_missing_scores(self):
        result = classify_vulnerability(
            cvss_score=None,
            epss_score=None,
            known_ransomware_use="Unknown",
        )

        self.assertEqual(result["priority"], 4)
        self.assertIn(
            "EPSS score unavailable",
            result["reasons"],
        )
        self.assertIn(
            "CVSS score unavailable",
            result["reasons"],
        )


class TestPriorityRanking(unittest.TestCase):
    """Verify ranking against a temporary SQLite database."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = str(
            Path(self.temp_dir.name) / "priority_test.db"
        )

        with closing(sqlite3.connect(self.db_path)) as db:
            db.executescript(
                """
                CREATE TABLE threats (
                    id INTEGER PRIMARY KEY,
                    cve_id TEXT NOT NULL UNIQUE,
                    vendor TEXT,
                    product TEXT,
                    known_ransomware_use TEXT,
                    due_date TEXT,
                    required_action TEXT
                );

                CREATE TABLE threat_enrichment (
                    threat_id INTEGER PRIMARY KEY,
                    cvss_score REAL,
                    cvss_severity TEXT
                );

                CREATE TABLE epss_enrichment (
                    threat_id INTEGER PRIMARY KEY,
                    epss_score REAL,
                    epss_percentile REAL,
                    score_date TEXT
                );

                INSERT INTO threats
                    (id, cve_id, vendor, product,
                     known_ransomware_use)
                VALUES
                    (1, 'CVE-2026-0001', 'Vendor A',
                     'Product A', 'Unknown'),
                    (2, 'CVE-2026-0002', 'Vendor B',
                     'Product B', 'Known'),
                    (3, 'CVE-2026-0003', 'Vendor C',
                     'Product C', 'Unknown'),
                    (4, 'CVE-2026-0004', 'Vendor D',
                     'Product D', 'Unknown');

                INSERT INTO threat_enrichment
                    (threat_id, cvss_score, cvss_severity)
                VALUES
                    (1, 9.8, 'CRITICAL'),
                    (2, 5.0, 'MEDIUM'),
                    (3, 8.0, 'HIGH');

                INSERT INTO epss_enrichment
                    (threat_id, epss_score,
                     epss_percentile, score_date)
                VALUES
                    (1, 0.90, 0.99, '2026-10-23'),
                    (2, 0.10, 0.50, '2026-10-23'),
                    (3, 0.40, 0.80, '2026-10-23');
                """
            )
            db.commit()

    def test_ranking_order(self):
        results = rank_vulnerabilities(
            db_path=self.db_path,
            limit=10,
        )

        self.assertEqual(len(results), 4)

        self.assertEqual(
            [item["cve_id"] for item in results],
            [
                "CVE-2026-0002",
                "CVE-2026-0001",
                "CVE-2026-0003",
                "CVE-2026-0004",
            ],
        )

        self.assertEqual(
            [item["priority"] for item in results],
            [1, 1, 2, 4],
        )

    def test_missing_enrichment_is_retained(self):
        results = rank_vulnerabilities(
            db_path=self.db_path,
            limit=10,
        )

        missing = next(
            item for item in results
            if item["cve_id"] == "CVE-2026-0004"
        )

        self.assertIsNone(missing["cvss_score"])
        self.assertIsNone(missing["epss_score"])
        self.assertEqual(missing["priority"], 4)

    def test_limit_validation(self):
        with self.assertRaises(ValueError):
            rank_vulnerabilities(
                db_path=self.db_path,
                limit=0,
            )


if __name__ == "__main__":
    unittest.main()
