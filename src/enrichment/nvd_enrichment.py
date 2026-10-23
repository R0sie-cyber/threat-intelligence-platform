
"""
SignalIQ NVD enrichment pipeline.

Supports:
- Incremental enrichment of new CVEs
- Controlled refreshes of existing CVEs
- Manual refresh of a specific CVE
- Selective retries for temporary API failures
- SQLite upserts and enrichment timestamps
"""

import argparse
import random
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import requests

from src.database.connection import get_database_connection


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_REFRESH_DAYS = 7
DEFAULT_BATCH_SIZE = 10
REQUEST_DELAY_SECONDS = 6
MAX_RETRIES = 3

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def utc_now():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def load_threats(mode="new", limit=DEFAULT_BATCH_SIZE,
                 refresh_days=DEFAULT_REFRESH_DAYS, cve_id=None):
    """
    Select CVEs for enrichment.

    Modes:
        new: CVEs without enrichment records.
        stale: Timestamped enrichment older than refresh_days.
        legacy: Existing enrichment without a timestamp.
        force: Refresh a specified CVE regardless of status.
    """
    connection = get_database_connection()

    try:
        if mode == "force":
            if not cve_id:
                raise ValueError("A CVE ID is required for force mode.")

            rows = connection.execute(
                """
                SELECT id, cve_id
                FROM threats
                WHERE cve_id = ?
                """,
                (cve_id.upper(),)
            ).fetchall()

            return rows

        if mode == "new":
            query = """
                SELECT t.id, t.cve_id
                FROM threats t
                LEFT JOIN threat_enrichment e
                    ON t.id = e.threat_id
                WHERE e.id IS NULL
                ORDER BY t.id ASC
                LIMIT ?
            """
            parameters = (limit,)

        elif mode == "legacy":
            query = """
                SELECT t.id, t.cve_id
                FROM threats t
                JOIN threat_enrichment e
                    ON t.id = e.threat_id
                WHERE e.last_enriched_at IS NULL
                ORDER BY t.id ASC
                LIMIT ?
            """
            parameters = (limit,)

        elif mode == "stale":
            cutoff = (
                datetime.now(timezone.utc)
                - timedelta(days=refresh_days)
            ).isoformat()

            query = """
                SELECT t.id, t.cve_id
                FROM threats t
                JOIN threat_enrichment e
                    ON t.id = e.threat_id
                WHERE e.last_enriched_at IS NOT NULL
                  AND e.last_enriched_at <= ?
                ORDER BY e.last_enriched_at ASC
                LIMIT ?
            """
            parameters = (cutoff, limit)

        else:
            raise ValueError(f"Unsupported mode: {mode}")

        return connection.execute(query, parameters).fetchall()

    finally:
        connection.close()


def fetch_nvd_data(cve_id, max_retries=MAX_RETRIES):
    """Retrieve NVD data with selective retry handling."""
    for attempt in range(max_retries):
        try:
            response = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                timeout=30
            )

            if response.status_code in RETRYABLE_STATUS_CODES:
                if attempt == max_retries - 1:
                    response.raise_for_status()

                retry_after = response.headers.get("Retry-After")

                if retry_after and retry_after.isdigit():
                    wait_time = min(int(retry_after), 120)
                else:
                    wait_time = min(
                        2 ** attempt + random.uniform(0, 1),
                        60
                    )

                print(
                    f"Temporary HTTP {response.status_code} "
                    f"for {cve_id}. Retrying in "
                    f"{wait_time:.1f} seconds..."
                )
                time.sleep(wait_time)
                continue

            response.raise_for_status()
            return response.json()

        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as error:
            if attempt == max_retries - 1:
                raise

            wait_time = min(
                2 ** attempt + random.uniform(0, 1),
                60
            )

            print(
                f"Network error for {cve_id}: {error}. "
                f"Retrying in {wait_time:.1f} seconds..."
            )
            time.sleep(wait_time)

    raise RuntimeError(f"Failed to retrieve NVD data for {cve_id}")


def extract_enrichment_fields(cve):
    """Extract the NVD fields used by SignalIQ."""
    published_date = cve.get("published")
    last_modified = cve.get("lastModified")

    description = next(
        (
            item.get("value")
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en"
        ),
        None
    )

    metrics = cve.get("metrics", {})

    cvss_score = None
    cvss_severity = None

    for version in (
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ):
        entries = metrics.get(version, [])

        if not entries:
            continue

        metric = entries[0]
        cvss_data = metric.get("cvssData", {})

        cvss_score = cvss_data.get("baseScore")
        cvss_severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
        )
        break

    cwe = None

    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            if item.get("lang") == "en":
                cwe = item.get("value")
                break

        if cwe:
            break

    return {
        "published_date": published_date,
        "last_modified": last_modified,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe": cwe
    }


def upsert_enrichment(threat_id, enrichment):
    """Insert or update enrichment for a threat."""
    connection = get_database_connection()

    try:
        connection.execute(
            """
            INSERT INTO threat_enrichment (
                threat_id,
                cvss_score,
                cvss_severity,
                cwe,
                published_date,
                last_modified,
                description,
                last_enriched_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(threat_id) DO UPDATE SET
                cvss_score = COALESCE(
                    excluded.cvss_score,
                    threat_enrichment.cvss_score
                ),
                cvss_severity = COALESCE(
                    excluded.cvss_severity,
                    threat_enrichment.cvss_severity
                ),
                cwe = COALESCE(
                    excluded.cwe,
                    threat_enrichment.cwe
                ),
                published_date = COALESCE(
                    excluded.published_date,
                    threat_enrichment.published_date
                ),
                last_modified = COALESCE(
                    excluded.last_modified,
                    threat_enrichment.last_modified
                ),
                description = COALESCE(
                    excluded.description,
                    threat_enrichment.description
                ),
                last_enriched_at = excluded.last_enriched_at
            """,
            (
                threat_id,
                enrichment["cvss_score"],
                enrichment["cvss_severity"],
                enrichment["cwe"],
                enrichment["published_date"],
                enrichment["last_modified"],
                enrichment["description"],
                utc_now()
            )
        )

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def run_enrichment(mode="new", limit=DEFAULT_BATCH_SIZE,
                   refresh_days=DEFAULT_REFRESH_DAYS, cve_id=None):
    """Execute a controlled batch of NVD enrichment."""
    threats = load_threats(
        mode=mode,
        limit=limit,
        refresh_days=refresh_days,
        cve_id=cve_id
    )

    print(f"\nMode: {mode}")
    print(f"Selected vulnerabilities: {len(threats)}")

    successful = 0
    failed = 0

    for index, (threat_id, current_cve) in enumerate(
        threats, start=1
    ):
        print(
            f"\n[{index}/{len(threats)}] "
            f"Processing {current_cve}"
        )

        try:
            data = fetch_nvd_data(current_cve)

            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                raise ValueError(
                    f"No NVD vulnerability data for {current_cve}"
                )

            cve = vulnerabilities[0]["cve"]

            if cve.get("id", "").upper() != current_cve.upper():
                raise ValueError(
                    "NVD response CVE does not match requested CVE."
                )

            enrichment = extract_enrichment_fields(cve)

            upsert_enrichment(threat_id, enrichment)

            successful += 1
            print(f"Saved enrichment for {current_cve}")

        except (
            requests.exceptions.RequestException,
            ValueError,
            KeyError,
            sqlite3.Error
        ) as error:
            failed += 1
            print(f"Failed: {current_cve}: {error}")

        if index < len(threats):
            time.sleep(REQUEST_DELAY_SECONDS)

    print("\nEnrichment Summary")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")

    return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description="SignalIQ NVD enrichment pipeline"
    )

    parser.add_argument(
        "--mode",
        choices=["new", "stale", "legacy", "force"],
        default="new"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_BATCH_SIZE
    )

    parser.add_argument(
        "--refresh-days",
        type=int,
        default=DEFAULT_REFRESH_DAYS
    )

    parser.add_argument(
        "--cve",
        type=str
    )

    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1.")

    if args.refresh_days < 0:
        parser.error("--refresh-days cannot be negative.")

    if args.mode == "force" and not args.cve:
        parser.error("--cve is required for force mode.")

    if args.cve and args.mode != "force":
        parser.error("--cve can only be used with force mode.")

    success = run_enrichment(
        mode=args.mode,
        limit=args.limit,
        refresh_days=args.refresh_days,
        cve_id=args.cve
    )

    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
