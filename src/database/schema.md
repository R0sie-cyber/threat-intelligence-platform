# Database Design

## Overview

The Threat Intelligence Platform stores normalized and enriched threat intelligence in a structured database that supports searching, filtering, enrichment, reporting, and future automation.

The database is designed to separate raw threat intelligence from enriched intelligence so additional enrichment services can be added without changing the overall schema.

---

# Entity Relationship Overview

Threat Sources
        │
        ▼
Threats
        │
        ├──────── Indicators
        │
        ├──────── CVEs
        │
        ├──────── MITRE Techniques
        │
        └──────── Reports

---

## Threats

Stores every normalized threat collected by the platform.

### Purpose

Acts as the central record for every threat.

### Columns

| Column | Description |
|---------|-------------|
| threat_id | Unique threat identifier |
| title | Threat title |
| description | Threat summary |
| source | Source feed |
| severity | Risk level |
| first_seen | First collection date |
| last_updated | Most recent update |
| status | Active / Archived |

---

## Indicators

Stores Indicators of Compromise (IOCs).

### Purpose

Stores artifacts associated with each threat.

### Columns

| Column | Description |
|---------|-------------|
| indicator_id | Unique IOC |
| threat_id | Related threat |
| type | IP, Domain, URL, Hash |
| value | IOC value |

---

## MITRE Mapping

Stores ATT&CK mappings.

### Purpose

Maps threats to attacker behavior.

### Columns

| Column | Description |
|---------|-------------|
| mitre_id | Mapping ID |
| threat_id | Related threat |
| tactic | ATT&CK tactic |
| technique | ATT&CK technique |

---

## CVEs

Stores vulnerability information.

### Purpose

Provides vulnerability context.

### Columns

| Column | Description |
|---------|-------------|
| cve_id | CVE identifier |
| threat_id | Related threat |
| cvss | CVSS score |
| epss | EPSS probability |
| exploit_available | Yes / No |

---

## Reports

Stores generated reports.

### Purpose

Keeps a history of analyst reports.

### Columns

| Column | Description |
|---------|-------------|
| report_id | Report ID |.\.venv\Scripts\Activate
| generated_date | Report creation date |
| report_type | Executive / Technical / Weekly |
| threat_count | Number of threats included |

---

## Future Tables

These will be added in later versions.

- Users
- Threat Actors
- Saved Investigations
- Analyst Notes
- Collections