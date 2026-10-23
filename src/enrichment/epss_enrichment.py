
"""
SignalIQ EPSS enrichment.

Retrieves exploitation probability data from the FIRST EPSS API
and stores it in SQLite.
"""

import sqlite3
from contextlib import closing
from datetime import datetime, timezone

import requests


EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_data(cve_id):
    """Retrieve current EPSS data for a single CVE."""
    response = requests.get(
        EPSS_API_URL,
        params={"cve": cve_id},
        timeout=30,
    )
    response.raise_for_status()

    records = response.json().get("data", [])

    if not records:
        return None

    record = records[0]

    if record.get("cve") != cve_id:
        raise ValueError(
            f"Unexpected CVE in EPSS response: {record.get('cve')}"
        )

    return {
        "cve_id": record["cve"],
        "epss_score": float(record["epss"]),
        "epss_percentile": float(record["percentile"]),
        "score_date": record["date"],
    }


def fetch_epss_batch(cve_ids):
    """Retrieve EPSS data for multiple CVEs in one API request."""
    if not cve_ids:
        return {}

    unique_cves = list(dict.fromkeys(cve_ids))

    response = requests.get(
        EPSS_API_URL,
        params={"cve": ",".join(unique_cves)},
        timeout=30,
    )
    response.raise_for_status()

    records = response.json().get("data", [])
    results = {}

    for record in records:
        cve_id = record.get("cve")

        if cve_id not in unique_cves:
            raise ValueError(
                f"Unexpected CVE in EPSS batch response: {cve_id}"
            )

        score = float(record["epss"])
        percentile = float(record["percentile"])

        if not (0 <= score <= 1 and 0 <= percentile <= 1):
            raise ValueError(
                f"Invalid EPSS values returned for {cve_id}"
            )

        results[cve_id] = {
            "cve_id": cve_id,
            "epss_score": score,
            "epss_percentile": percentile,
            "score_date": record["date"],
        }

    return results


def save_epss_data(cve_id, epss_data, db_path="signaliq.db"):
    """Insert or update EPSS data for an existing vulnerability."""
    if epss_data is None:
        raise ValueError("Cannot save empty EPSS data.")

    if epss_data["cve_id"] != cve_id:
        raise ValueError("EPSS response CVE does not match the requested CVE.")

    score = float(epss_data["epss_score"])
    percentile = float(epss_data["epss_percentile"])

    if not (0 <= score <= 1 and 0 <= percentile <= 1):
        raise ValueError("EPSS score and percentile must be between 0 and 1.")

    with closing(sqlite3.connect(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        threat = connection.execute(
            "SELECT id FROM threats WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()

        if threat is None:
            raise ValueError(
                f"Cannot save EPSS data: {cve_id} does not exist in threats."
            )

        threat_id = threat[0]
        enriched_at = datetime.now(timezone.utc).isoformat()

        with connection:
            connection.execute(
                """
                INSERT INTO epss_enrichment (
                    threat_id,
                    epss_score,
                    epss_percentile,
                    score_date,
                    last_enriched_at
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(threat_id) DO UPDATE SET
                    epss_score = excluded.epss_score,
                    epss_percentile = excluded.epss_percentile,
                    score_date = excluded.score_date,
                    last_enriched_at = excluded.last_enriched_at
                """,
                (
                    threat_id,
                    score,
                    percentile,
                    epss_data["score_date"],
                    enriched_at,
                ),
            )

    return threat_id


def save_epss_lookup_status(
    cve_id,
    lookup_status,
    db_path="signaliq.db",
):
    """Record a successful EPSS lookup as found or not_found."""
    if lookup_status not in ("found", "not_found"):
        raise ValueError(
            "Lookup status must be 'found' or 'not_found'."
        )

    with closing(sqlite3.connect(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        threat = connection.execute(
            "SELECT id FROM threats WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()

        if threat is None:
            raise ValueError(
                f"Cannot record EPSS lookup: {cve_id} is not in threats."
            )

        threat_id = threat[0]
        checked_at = datetime.now(timezone.utc).isoformat()

        with connection:
            connection.execute(
                """
                INSERT INTO epss_lookup_status (
                    threat_id,
                    lookup_status,
                    last_checked_at
                )
                VALUES (?, ?, ?)
                ON CONFLICT(threat_id) DO UPDATE SET
                    lookup_status = excluded.lookup_status,
                    last_checked_at = excluded.last_checked_at
                """,
                (threat_id, lookup_status, checked_at),
            )

    return threat_id


def load_missing_epss_cves(limit=10, db_path="signaliq.db"):
    """Select CVEs without EPSS data or a recorded successful lookup."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("Batch limit must be a positive integer.")

    with closing(sqlite3.connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT t.cve_id
            FROM threats AS t
            LEFT JOIN epss_enrichment AS e
                ON t.id = e.threat_id
            LEFT JOIN epss_lookup_status AS s
                ON t.id = s.threat_id
            WHERE e.threat_id IS NULL
              AND s.threat_id IS NULL
            ORDER BY t.cve_id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [row[0] for row in rows]


def enrich_epss_batch(cve_ids, db_path="signaliq.db"):
    """Retrieve, save, and track EPSS results for a batch of CVEs."""
    unique_cves = list(dict.fromkeys(cve_ids))

    if not unique_cves:
        return {"saved": 0, "missing": 0, "failed": 0}

    results = fetch_epss_batch(unique_cves)

    saved = 0
    missing = 0
    failed = 0

    for cve_id in unique_cves:
        epss_data = results.get(cve_id)

        try:
            if epss_data is None:
                save_epss_lookup_status(
                    cve_id, "not_found", db_path
                )
                print(f"No EPSS score available: {cve_id}")
                missing += 1
                continue

            threat_id = save_epss_data(
                cve_id, epss_data, db_path
            )

            save_epss_lookup_status(
                cve_id, "found", db_path
            )

            print(
                f"Saved EPSS: {cve_id} "
                f"(threat ID: {threat_id})"
            )
            saved += 1

        except (ValueError, KeyError, TypeError, sqlite3.Error) as error:
            print(f"Failed to process {cve_id}: {error}")
            failed += 1

    return {
        "saved": saved,
        "missing": missing,
        "failed": failed,
    }


def run_epss_collection(
    batch_size=50,
    max_batches=1,
    db_path="signaliq.db",
):
    """Process missing EPSS records in controlled batches."""
    if (
        not isinstance(batch_size, int)
        or isinstance(batch_size, bool)
        or not 1 <= batch_size <= 50
    ):
        raise ValueError("Batch size must be between 1 and 50.")

    if (
        not isinstance(max_batches, int)
        or isinstance(max_batches, bool)
        or max_batches < 1
    ):
        raise ValueError("max_batches must be a positive integer.")

    totals = {"saved": 0, "missing": 0, "failed": 0}

    for batch_number in range(1, max_batches + 1):
        cves = load_missing_epss_cves(
            limit=batch_size,
            db_path=db_path,
        )

        if not cves:
            print("No unprocessed CVEs remain.")
            break

        print(
            f"Processing batch {batch_number}/{max_batches} "
            f"({len(cves)} CVEs)..."
        )

        try:
            results = enrich_epss_batch(cves, db_path)
        except (
            requests.RequestException,
            ValueError,
            KeyError,
            TypeError,
        ) as error:
            print(
                f"Batch stopped due to an API or response error: {error}"
            )
            break

        for key in totals:
            totals[key] += results[key]

        print(f"Batch {batch_number} results: {results}")

        if results["failed"] > 0:
            print("Stopping because some records failed to save.")
            break

    print(f"Collection totals: {totals}")
    return totals


if __name__ == "__main__":
    test_cve = "CVE-2021-44228"

    print(f"Fetching EPSS data for {test_cve}...")

    result = fetch_epss_data(test_cve)

    if result is None:
        print("No EPSS data available for this CVE.")
    else:
        print("EPSS response:")
        for field, value in result.items():
            print(f"  {field}: {value}")
