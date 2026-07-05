"""
cisa_collector.py

Collects the latest Known Exploited Vulnerabilities (KEV)
from the Cybersecurity and Infrastructure Security Agency (CISA)
and stores the raw threat intelligence locally.

Author: Roselyn Ojo
Project: SignalIQ
Codename: Project Atlas
"""

import json
from pathlib import Path
from datetime import datetime

import requests


# ============================================================
# Configuration
# ============================================================

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

OUTPUT_DIRECTORY = Path("sample_data")
OUTPUT_FILE = OUTPUT_DIRECTORY / "cisa_raw.json"


# ============================================================
# Functions
# ============================================================

def fetch_cisa_kev():
    """
    Download the latest CISA Known Exploited Vulnerabilities feed.
    """

    print("\n======================================")
    print(" SignalIQ Threat Collection")
    print("======================================\n")

    print("Connecting to CISA KEV feed...")

    response = requests.get(CISA_KEV_URL, timeout=30)

    response.raise_for_status()

    print("Connection successful.\n")

    return response.json()


def save_raw_data(data):
    """
    Save the raw JSON response locally.
    """

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    print(f"Raw threat intelligence saved to:")
    print(f"   {OUTPUT_FILE}\n")


def display_summary(data):
    """
    Display a summary of the downloaded threat feed.
    """

    vulnerabilities = data.get("vulnerabilities", [])

    print("Collection Summary")
    print("------------------")
    print(f"Collection Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Threat Feed     : CISA Known Exploited Vulnerabilities")
    print(f"Vulnerabilities : {len(vulnerabilities)}\n")


# ============================================================
# Main
# ============================================================

def main():

    try:

        data = fetch_cisa_kev()

        display_summary(data)

        print("Saving raw threat intelligence...\n")

        save_raw_data(data)

        print("Collection completed successfully.\n")

    except requests.exceptions.RequestException as error:

        print("Collection failed.")
        print(error)


if __name__ == "__main__":
    main()