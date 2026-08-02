import json
import requests
import time
from pathlib import Path
from src.database.connection import get_database_connection

# Define project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def load_threats():
    """
    Retrieve all stored threats from the database.
    """
    # Connect to (or create) the SQLite database
    connection = get_database_connection()
        
    # Create a cursor
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, cve_id
        FROM threats
        ORDER BY id ASC
        """
)

    # Fetch all rows
    threats = cursor.fetchall()

    # Close resources
    cursor.close()
    connection.close()

    return threats


def fetch_nvd_data(cve_id, max_retries=5):
    """
    Retrieve enrichment data for a single CVE from the NVD API.
    """

    print(f"Fetching NVD data for {cve_id}...")

    for attempt in range(max_retries):

        try:
            response = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                timeout=30
            )

            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as error:

            if attempt == max_retries - 1:
                raise

            wait_time = 2 ** attempt

            print(
                f"Request failed: {error}. "
                f"Retrying in {wait_time} seconds..."
            )

            time.sleep(wait_time)


def extract_enrichment_fields(cve):
    """
    Extract the enrichment fields needed from the NVD response.
    Handles different CVSS versions.
    """

    published_date = cve.get("published")
    last_modified = cve.get("lastModified")

    description = None
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value")
            break

    metrics = cve.get("metrics", {})

    cvss_score = None
    cvss_severity = None

    # Try CVSS v3.1 first
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]

        cvss_score = cvss_data.get("baseScore")
        cvss_severity = cvss_data.get("baseSeverity")

    # Fall back to CVSS v3.0
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]

        cvss_score = cvss_data.get("baseScore")
        cvss_severity = cvss_data.get("baseSeverity")

    # Fall back to CVSS v2
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]

        cvss_score = cvss_data.get("baseScore")

        # CVSS v2 does not always include baseSeverity
        cvss_severity = metrics["cvssMetricV2"][0].get("baseSeverity")


    # Extract CWE information safely
    cwe = None

    weaknesses = cve.get("weaknesses", [])

    if weaknesses:
        descriptions = weaknesses[0].get("description", [])

        if descriptions:
            cwe = descriptions[0].get("value")


    return {
        "published_date": published_date,
        "last_modified": last_modified,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe": cwe
    }

def insert_enrichment(threat_id, enrichment):
    """
    Insert enrichment data into the threat_enrichment table.
    """

    connection = get_database_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT OR IGNORE INTO threat_enrichment (
            threat_id,
            cvss_score,
            cvss_severity,
            cwe,
            published_date,
            last_modified,
            description
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            threat_id,
            enrichment["cvss_score"],
            enrichment["cvss_severity"],
            enrichment["cwe"],
            enrichment["published_date"],
            enrichment["last_modified"],
            enrichment["description"]
        )
    )

    connection.commit()

    cursor.close()
    connection.close()


def main():
    """
    Enrich all stored threats using the NVD API.
    """

    # Load all threats from the database
    threats = load_threats()

    print(f"Loaded {len(threats)} threats.\n")

    successful = 0
    failed = 0

    # Process every stored threat
    for index, (threat_id, cve_id) in enumerate(threats, start=1):

        print("=" * 60)
        print(f"Processing {index}/{len(threats)}")
        print(f"Threat ID: {threat_id}")
        print(f"CVE: {cve_id}")

        try:
            # Fetch NVD data
            nvd_data = fetch_nvd_data(cve_id)

            # Shortcut to the CVE object
            cve = nvd_data["vulnerabilities"][0]["cve"]

            # Extract enrichment fields
            enrichment = extract_enrichment_fields(cve)

            # Save enrichment
            insert_enrichment(threat_id, enrichment)

            successful += 1

            print(f"✓ Enrichment saved successfully for {cve_id}.")

            # Display extracted data
            print(f"Published Date: {enrichment['published_date']}")
            print(f"Last Modified: {enrichment['last_modified']}")
            print(f"Description: {enrichment['description']}")
            print(f"CVSS Score: {enrichment['cvss_score']}")
            print(f"CVSS Severity: {enrichment['cvss_severity']}")
            print(f"CWE: {enrichment['cwe']}")

        except Exception as error:

            failed += 1

            print(f"✗ Failed to enrich {cve_id}")
            print(f"Reason: {error}")

        # Pause between requests to reduce API rate limiting
        time.sleep(1)

    print("\n" + "=" * 60)
    print("Enrichment Complete")
    print("=" * 60)
    print(f"Total Threats: {len(threats)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")


if __name__ == "__main__":
    main()