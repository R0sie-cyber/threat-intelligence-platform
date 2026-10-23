
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.enrichment.nvd_enrichment import upsert_enrichment


class TestNVDUpsert(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self.temp_dir.name) / "test_signaliq.db"
        )

        connection = sqlite3.connect(self.database_path)

        connection.executescript("""
            CREATE TABLE threats (
                id INTEGER PRIMARY KEY,
                cve_id TEXT NOT NULL UNIQUE
            );

            CREATE TABLE threat_enrichment (
                id INTEGER PRIMARY KEY,
                threat_id INTEGER NOT NULL UNIQUE,
                cvss_score REAL,
                cvss_severity TEXT,
                cwe TEXT,
                published_date TEXT,
                last_modified TEXT,
                description TEXT,
                last_enriched_at TEXT,
                FOREIGN KEY (threat_id)
                    REFERENCES threats(id)
            );

            INSERT INTO threats (id, cve_id)
            VALUES (1, 'CVE-2026-16232');
        """)

        connection.close()

        self.connection_patch = patch(
            "src.enrichment.nvd_enrichment.get_database_connection",
            side_effect=lambda: sqlite3.connect(self.database_path)
        )
        self.connection_patch.start()

    def tearDown(self):
        self.connection_patch.stop()
        self.temp_dir.cleanup()

    def test_upsert_preserves_existing_values(self):
        initial = {
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cwe": "CWE-79",
            "published_date": "2026-01-01",
            "last_modified": "2026-08-10",
            "description": "Original description"
        }

        upsert_enrichment(1, initial)

        refreshed = {
            "cvss_score": None,
            "cvss_severity": None,
            "cwe": None,
            "published_date": None,
            "last_modified": "2026-10-23",
            "description": None
        }

        upsert_enrichment(1, refreshed)

        connection = sqlite3.connect(self.database_path)

        row = connection.execute("""
            SELECT
                cvss_score,
                cvss_severity,
                cwe,
                description,
                last_modified,
                last_enriched_at
            FROM threat_enrichment
            WHERE threat_id = 1
        """).fetchone()

        count = connection.execute("""
            SELECT COUNT(*)
            FROM threat_enrichment
        """).fetchone()[0]

        connection.close()

        self.assertEqual(row[0], 9.8)
        self.assertEqual(row[1], "CRITICAL")
        self.assertEqual(row[2], "CWE-79")
        self.assertEqual(row[3], "Original description")
        self.assertEqual(row[4], "2026-10-23")
        self.assertIsNotNone(row[5])
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()

