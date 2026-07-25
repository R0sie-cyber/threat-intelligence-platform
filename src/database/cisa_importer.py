# Purpose: Read the raw CISA JSON file, extract vulnerability records, transform them into your database format, and insert them into the threats table.
# Responsibility: Read the CISA KEV feed. Insert vulnerabilities into the threats table.

import json
from pathlib import Path
from datetime import datetime

from connection import get_database_connection

# Define project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# DATABASE_PATH = PROJECT_ROOT / "signaliq.db"
CISA_DATA_PATH = PROJECT_ROOT / "sample_data" / "cisa_raw.json"

# Reads the JSON file.
def load_cisa_data():
    """
    Read the raw CISA KEV JSON file and return the list of vulnerabilities.
    """
    # Open the raw CISA KEV JSON file
    with open(CISA_DATA_PATH, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Extract the list of vulnerabilities
    vulnerabilities = data["vulnerabilities"]
    
    return vulnerabilities

# Inserts the data and reports what happened during the import.
def insert_threats(vulnerabilities):
    """
    Insert CISA KEV vulnerabilities into the threats table.
    """
    # Connect to (or create) the SQLite database
    connection = get_database_connection()
        
    # Create a cursor
    cursor = connection.cursor()

    # Create counters
    processed = 0
    inserted = 0
    skipped = 0

    for vulnerability in vulnerabilities:

        processed += 1

        # Map JSON fields to database fields
        cve_id = vulnerability["cveID"]
        vendor = vulnerability["vendorProject"]
        product = vulnerability["product"]
        vulnerability_name = vulnerability["vulnerabilityName"]
        date_added = vulnerability["dateAdded"]
        due_date = vulnerability["dueDate"]
        required_action = vulnerability["requiredAction"]
        known_ransomware_use = vulnerability["knownRansomwareCampaignUse"]
        notes = vulnerability["notes"]


        # Create timestamp
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT OR IGNORE INTO threats (
                cve_id,
                vendor,
                product,
                vulnerability_name,
                date_added,
                due_date,
                required_action,
                known_ransomware_use,
                notes,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                vendor,
                product,
                vulnerability_name,
                date_added,
                due_date,
                required_action,
                known_ransomware_use,
                notes,
                created_at
            )
        )

        # Check whether a new row was inserted
        if cursor.rowcount == 1:
            inserted += 1
        else:
            skipped += 1

    # Save all changes
    connection.commit()

    # Close resources
    cursor.close()
    connection.close()

    # Display import summary
    print("\n======================================")
    print(" SignalIQ Database Import Summary")
    print("======================================")
    print(f"Threats Processed : {processed}")
    print(f"New Threats Added : {inserted}")
    print(f"Duplicates Skipped : {skipped}")
    print("\nDatabase population completed successfully.\n")

# Coordinates the overall workflow.
def main():
    """
    Execute the database population pipeline.
    """
    vulnerabilities = load_cisa_data()

    print(f"Loaded {len(vulnerabilities)} vulnerabilities.")
    print("Importing vulnerabilities into the database...\n")

    # call insert_threats
    insert_threats(vulnerabilities)

if __name__ == "__main__":
    main()