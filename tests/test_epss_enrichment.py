
"""
Automated tests for SignalIQ EPSS enrichment.

Uses temporary SQLite databases and mocked API responses.
No live API requests or production database changes.
"""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from src.enrichment.epss_enrichment import (
    enrich_epss_batch,
    load_missing_epss_cves,
)


class TestEPSSEnrichment(unittest.TestCase):
    """Test EPSS enrichment and lookup tracking."""

    def setUp(self):
        """Create a temporary SQLite database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = str(Path(self.temp_dir.name) / "test.db")

        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.executescript(
                """
                CREATE TABLE threats (
                    id INTEGER PRIMARY KEY,
                    cve_id TEXT NOT NULL UNIQUE
                );

                CREATE TABLE epss_enrichment (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id INTEGER NOT NULL UNIQUE,
                    epss_score REAL NOT NULL,
                    epss_percentile REAL NOT NULL,
                    score_date TEXT NOT NULL,
                    last_enriched_at TEXT NOT NULL,
                    FOREIGN KEY (threat_id) REFERENCES threats(id)
                );

                CREATE TABLE epss_lookup_status (
                    threat_id INTEGER PRIMARY KEY,
                    lookup_status TEXT NOT NULL
                        CHECK (
                            lookup_status IN ('found', 'not_found')
                        ),
                    last_checked_at TEXT NOT NULL,
                    FOREIGN KEY (threat_id) REFERENCES threats(id)
                );

                INSERT INTO threats (id, cve_id)
                VALUES
                    (1, 'CVE-2021-44228'),
                    (2, 'CVE-2023-34362');
                """
            )
            connection.commit()

    @patch("src.enrichment.epss_enrichment.fetch_epss_batch")
    def test_batch_saves_found_and_missing(self, mock_fetch):
        """Verify successful and unavailable EPSS lookups."""
        mock_fetch.return_value = {
            "CVE-2021-44228": {
                "cve_id": "CVE-2021-44228",
                "epss_score": 0.95,
                "epss_percentile": 0.99,
                "score_date": "2026-10-23",
            }
        }

        results = enrich_epss_batch(
            ["CVE-2021-44228", "CVE-2023-34362"],
            self.db_path,
        )

        self.assertEqual(
            results,
            {"saved": 1, "missing": 1, "failed": 0},
        )

        with closing(sqlite3.connect(self.db_path)) as connection:
            statuses = connection.execute(
                """
                SELECT t.cve_id, s.lookup_status
                FROM epss_lookup_status AS s
                JOIN threats AS t
                    ON t.id = s.threat_id
                ORDER BY t.cve_id
                """
            ).fetchall()

        self.assertEqual(
            statuses,
            [
                ("CVE-2021-44228", "found"),
                ("CVE-2023-34362", "not_found"),
            ],
        )

    def test_missing_selection_excludes_checked_cves(self):
        """Verify checked CVEs are excluded from initial collection."""
        with closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO epss_lookup_status (
                        threat_id,
                        lookup_status,
                        last_checked_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (1, "not_found", "2026-10-23"),
                )

        selected = load_missing_epss_cves(
            limit=10,
            db_path=self.db_path,
        )

        self.assertEqual(
            selected,
            ["CVE-2023-34362"],
        )

    @patch("src.enrichment.epss_enrichment.fetch_epss_batch")
    def test_upsert_does_not_duplicate(self, mock_fetch):
        """Verify an EPSS refresh updates rather than duplicates."""
        mock_fetch.return_value = {
            "CVE-2021-44228": {
                "cve_id": "CVE-2021-44228",
                "epss_score": 0.5,
                "epss_percentile": 0.75,
                "score_date": "2026-10-23",
            }
        }

        first_result = enrich_epss_batch(
            ["CVE-2021-44228"],
            self.db_path,
        )

        self.assertEqual(first_result["saved"], 1)

        mock_fetch.return_value = {
            "CVE-2021-44228": {
                "cve_id": "CVE-2021-44228",
                "epss_score": 0.8,
                "epss_percentile": 0.9,
                "score_date": "2026-10-23",
            }
        }

        second_result = enrich_epss_batch(
            ["CVE-2021-44228"],
            self.db_path,
        )

        self.assertEqual(second_result["saved"], 1)

        with closing(sqlite3.connect(self.db_path)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM epss_enrichment"
            ).fetchone()[0]

            record = connection.execute(
                """
                SELECT epss_score, epss_percentile
                FROM epss_enrichment
                WHERE threat_id = 1
                """
            ).fetchone()

        self.assertEqual(count, 1)
        self.assertAlmostEqual(record[0], 0.8)
        self.assertAlmostEqual(record[1], 0.9)


if __name__ == "__main__":
    unittest.main()
