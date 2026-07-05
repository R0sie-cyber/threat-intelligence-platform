"""
Module: cisa_collector.py

Project: Project Atlas (Working Codename)

Purpose:
Download the latest Known Exploited Vulnerabilities (KEV) catalog
published by the Cybersecurity and Infrastructure Security Agency (CISA)
and store the raw response locally.

This module represents the Collection Layer of the Threat Intelligence
Platform. The collected data will later move through validation,
normalization, enrichment, risk scoring, storage, and visualization.

Author: Roselyn Ojo
Version: 1.0
"""

import json
from pathlib import Path

import requests


# ==========================================================
# Configuration
# ==========================================================

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

OUTPUT_FILE = Path("sample_data/cisa_raw.json")


# ==========================================================
# Future Improvements
# ==========================================================

# TODO:
# - Validate downloaded data before saving
# - Normalize field names across threat feeds
# - Record collection timestamps
# - Implement structured logging
# - Handle retry logic for temporary network failures
# - Integrate into the automated collection pipeline


# ==========================================================
# Collection Functions
# ==========================================================

def fetch_cisa_kev():
    """
    Retrieve the latest Known Exploited Vulnerabilities (KEV)
    catalog from CISA.

    Returns:
        dict: Parsed JSON response from the CISA KEV feed.
    """

    print("Connecting to CISA KEV...")

    response = requests.get(CISA_KEV_URL, timeout=30)

    # Raise an exception if the request fails
    response.raise_for_status()

    return response.json()


def save_raw_data(data):
    """
    Save the raw CISA response locally.

    Args:
        data (dict):
            Parsed JSON returned by the CISA API.
    """

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    print(f"Raw data saved to: {OUTPUT_FILE}")


# ==========================================================
# Main Pipeline
# ==========================================================

def main():
    """
    Execute the initial threat collection workflow.

    Workflow:
        1. Connect to CISA
        2. Download the KEV catalog
        3. Count vulnerabilities
        4. Save raw data locally
    """

    data = fetch_cisa_kev()

    vulnerabilities = data.get("vulnerabilities", [])

    print(f"Downloaded {len(vulnerabilities)} vulnerabilities.")

    print("Saving raw data...")

    save_raw_data(data)

    print("Collection complete.")


# ==========================================================
# Entry Point
# ==========================================================

if __name__ == "__main__":
    main()