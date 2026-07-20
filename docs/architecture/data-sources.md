# Data Sources

## Overview

The Threat Intelligence Platform collects intelligence from multiple trusted public sources. Each source provides different types of information that are later validated, normalized, and enriched before being stored in the platform.

---

## CISA Known Exploited Vulnerabilities (KEV)

### Purpose

Provides a curated catalog of vulnerabilities confirmed to be actively exploited in the wild.

### Why It Matters

Unlike general vulnerability databases, the KEV catalog focuses on vulnerabilities that represent immediate operational risk, making it valuable for prioritizing remediation efforts.

### Data Format

JSON

### Authentication

None

### Update Frequency

Frequently updated

### Important Fields

- CVE ID
- Vendor
- Product
- Vulnerability Name
- Date Added
- Required Action
- Due Date

### Documentation

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## National Vulnerability Database (NVD)

### Purpose

Provides standardized vulnerability information for publicly disclosed CVEs.

### Why It Matters

NVD enriches vulnerabilities with severity scores, technical metadata, and references that help analysts understand the potential impact of a vulnerability.

### Data Format

JSON

### Authentication

API Key (recommended)

### Update Frequency

Continuously updated

### Important Fields

- CVE
- Description
- CVSS Score
- Published Date
- Modified Date
- References

---

## AlienVault OTX

### Purpose

Provides community-generated threat intelligence, indicators of compromise (IOCs), and threat research shared by security professionals.

### Why It Matters

Threat feeds like OTX complement vulnerability databases by providing real-world intelligence observed and shared by the security community.

### Data Format

JSON

### Authentication

API Key

### Update Frequency

Continuously updated

### Important Fields

- Pulse Name
- Indicators
- Malware Families
- Threat Actors
- Tags

---

## AbuseIPDB

### Purpose

Provides reputation data for public IP addresses based on reported malicious activity.

### Why It Matters

IP reputation helps analysts quickly determine whether an address has a history of malicious behavior during an investigation.

### Data Format

JSON

### Authentication

API Key

### Update Frequency

Continuously updated

### Important Fields

- IP Address
- Abuse Confidence Score
- Country
- ISP
- Reports

---

## Future Sources

The platform is designed to support additional threat intelligence providers as the project evolves, including:

- MITRE ATT&CK
- EPSS
- VirusTotal
- CISA Cybersecurity Advisories (CSA)
- Microsoft Security Response Center (MSRC)
- GitHub Security Advisories

---

## Collection Workflow

```text
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
```
