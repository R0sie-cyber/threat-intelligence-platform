# Data Sources

## Overview

SignalIQ collects threat intelligence from trusted public sources. Each source provides different pieces of information that are validated, normalized, and enriched before being stored in the platform.

By separating collection from enrichment, SignalIQ can combine multiple intelligence sources while keeping the overall architecture modular and easy to extend.

---

# Current Data Sources

## CISA Known Exploited Vulnerabilities (KEV)

### Purpose

Provides a curated catalog of vulnerabilities confirmed to be actively exploited in the wild.

### Why It Matters

Unlike general vulnerability databases, the KEV catalog focuses on vulnerabilities that represent immediate operational risk, making it an ideal starting point for threat collection.

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

Provides standardized technical information for publicly disclosed vulnerabilities.

### Why It Matters

NVD enriches vulnerabilities with additional context that is not available in the CISA KEV catalog, including severity scores, weakness classifications, descriptions, and publication dates.

### Data Format

JSON

### Authentication

Optional (API key recommended for higher rate limits)

### Update Frequency

Continuously updated

### Important Fields

- CVE ID
- Description
- CVSS Score
- CVSS Severity
- CWE
- Published Date
- Last Modified Date

### Documentation

https://nvd.nist.gov/developers/vulnerabilities

---

# Planned Data Sources

The following integrations are planned for future versions of SignalIQ.

## MITRE ATT&CK

Provide mappings between vulnerabilities and attacker techniques.

## EPSS

Provide exploit probability scores to improve risk prioritization.

## AlienVault OTX

Provide community-generated indicators of compromise and threat intelligence.

## AbuseIPDB

Provide reputation data for public IP addresses involved in malicious activity.

## VirusTotal

Provide file, URL, and hash reputation.

## Microsoft Security Response Center (MSRC)

Provide Microsoft-specific security advisories.

## GitHub Security Advisories

Provide vulnerability information affecting open-source software.

---

# Current Collection Workflow

```text
CISA KEV API
        │
        ▼
Download JSON Response
        │
        ▼
Validate Response
        │
        ▼
Normalize Fields
        │
        ▼
Store Threat Records
        │
        ▼
Retrieve CVE IDs
        │
        ▼
NVD API
        │
        ▼
Extract Enrichment Data
        │
        ▼
Store Enrichment Records
        │
        ▼
Ready for Future Risk Prioritization
```