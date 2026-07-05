# Data Sources

## Overview

The Threat Intelligence Platform collects intelligence from multiple public sources. Each source provides different types of information that are later normalized and enriched before being stored in the platform.

---

# CISA Known Exploited Vulnerabilities (KEV)

## Purpose

Provides vulnerabilities confirmed to be actively exploited in the wild.

## Why It Matters

This feed helps prioritize vulnerabilities that represent immediate risk instead of theoretical vulnerabilities.

## Data Format

JSON

## Authentication

None

## Update Frequency

Frequently updated

## Important Fields

- CVE ID
- Vendor
- Product
- Vulnerability Name
- Date Added
- Required Action
- Due Date

## Documentation

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

# National Vulnerability Database (NVD)

## Purpose

Provides detailed vulnerability information for publicly disclosed CVEs.

## Why It Matters

Adds technical vulnerability metadata including CVSS scores.

## Data Format

JSON

## Authentication

API Key (recommended)

## Important Fields

- CVE
- Description
- CVSS Score
- Published Date
- Modified Date
- References

---

# AlienVault OTX

## Purpose

Provides community-generated threat intelligence and Indicators of Compromise.

## Why It Matters

Adds real-world indicators collected from security researchers.

## Data Format

JSON

## Authentication

API Key

## Important Fields

- Pulse Name
- Indicators
- Malware Families
- Threat Actors
- Tags

---

# AbuseIPDB

## Purpose

Provides reputation information for malicious IP addresses.

## Why It Matters

Adds IP reputation and abuse confidence scoring.

## Data Format

JSON

## Authentication

API Key

## Important Fields

- IP Address
- Abuse Confidence Score
- Country
- ISP
- Reports

# Collection Workflow

CISA API
      │
      ▼
Download JSON Response
      │
      ▼
Validate API Response
      │
      ▼
Normalize Field Names
      │
      ▼
Save Raw JSON
      │
      ▼
Store Clean Threat Objects
      │
      ▼
Ready for Enrichment