# SignalIQ

> SignalIQ is a threat intelligence platform designed to collect, enrich, and organize vulnerability intelligence from multiple public sources to help security analysts reduce manual investigation effort.

---

# Overview

Security analysts often rely on multiple intelligence sources when investigating vulnerabilities. Valuable context is distributed across platforms such as CISA, vulnerability databases, vendor advisories, and threat intelligence feeds.

Before meaningful analysis can begin, analysts often need to manually collect, compare, and organize information from multiple sources.

SignalIQ is being developed to simplify this workflow by creating a centralized threat intelligence pipeline that automatically collects vulnerability data, enriches it with additional context, and prepares it for future risk prioritization and visualization.

The project demonstrates cybersecurity, backend engineering, database design, API integration, and data engineering concepts through a modular architecture designed for future expansion.

---

# Why I Built This

While working through threat hunting labs and vulnerability research, I realized analysts often have to switch between multiple intelligence sources to investigate a single vulnerability.

CISA may identify whether a vulnerability is actively exploited, while other sources provide additional context such as severity ratings, weaknesses, and technical details.

I wanted to explore how this process could be automated.

Rather than replacing analysts, SignalIQ focuses on reducing repetitive data gathering and organization so security professionals can spend more time investigating threats and making decisions.

---

# Current Features

## Threat Intelligence Collection

- Collects vulnerability data from the CISA Known Exploited Vulnerabilities (KEV) catalog
- Validates API responses before processing
- Parses JSON threat intelligence data

## Database Persistence

- Stores vulnerability records in SQLite
- Uses a normalized database structure
- Separates collected threats from enrichment data
- Prevents duplicate records through database constraints

## Threat Enrichment

- Integrates with the National Vulnerability Database (NVD)
- Retrieves vulnerability metadata using CVE identifiers
- Extracts:
  - CVSS score
  - CVSS severity
  - CWE classification
  - Vulnerability descriptions
  - Published dates
  - Modified dates

## Engineering Practices

- Modular Python architecture
- API-based data collection
- Separation of collection and enrichment workflows
- Version-controlled development
- Engineering decision documentation

---

# System Architecture

```
Threat Intelligence Sources
        │
        ▼
Collection Layer
(CISA KEV)
        │
        ▼
Database Layer
(SQLite)
        │
        ▼
Enrichment Layer
(NVD)
        │
        ▼
Risk Prioritization
(Planned)
        │
        ▼
Dashboard & Reporting
(Planned)
```

Detailed architecture documentation:

```
docs/architecture/system-architecture.md
```

---

# Technology Stack

## Languages

- Python
- SQL

## Database

- SQLite

## Third-Party Libraries

- requests

## Python Standard Library

- sqlite3
- json

## Threat Intelligence Sources

- CISA Known Exploited Vulnerabilities (KEV)
- National Vulnerability Database (NVD)

## Documentation

- Markdown
- Git/GitHub

## Planned Technologies

- Microsoft Azure
- Power BI
- REST API
- AI/ML capabilities

---

# Repository Structure

```
threat-intelligence-platform/
│
├── docs/
│   ├── architecture/
│   │   ├── data-flow.md
│   │   ├── data-sources.md
│   │   ├── system-architecture.md
│   │   ├── system-overview.md
│   │   └── tech-stack.md
│   │
│   ├── engineering-journal/
│   │   ├── 2026-07-04-project-foundation.md
│   │   ├── 2026-07-24-persistence-layer.md
│   │   ├── 2026-07-27-cisa-ingestion.md
│   │   ├── 2026-07-30-database-normalization.md
│   │   └── 2026-08-01-nvd-enrichment.md
│   │
│   ├── roadmap/
│   │   ├── future-features.md
│   │   └── version-history.md
│
├── src/
│   ├── collection/
│   │   └── cisa_collector.py
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   ├── cisa_importer.py
│   │   ├── connection.py
│   │   ├── database.py
│   │   ├── schema.md
│   │   └── schema.sql
│   │
│   └── enrichment/
│       ├── __init__.py
│       └── nvd_enrichment.py
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/R0sie-cyber/threat-intelligence-platform.git
```

Navigate into the project:

```bash
cd threat-intelligence-platform
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment:

Windows:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

SignalIQ currently follows this workflow

```
CISA KEV API
      |
      |
      v
Threat Database
      |
      |
      v
NVD Enrichment
      |
      |
      v
Enriched Threat Intelligence
```
### Collect threat intelligence

```bash
python src/collection/cisa_collector.py
```

### Enrich vulnerability data

```bash
python src/enrichment/nvd_enrichment.py
```

---

# Development Roadmap

## Completed

- [x] Repository setup
- [x] Project architecture
- [x] Documentation structure
- [x] SQLite database implementation
- [x] CISA KEV collection pipeline
- [x] Database normalization
- [x] NVD enrichment pipeline

## In Progress

- [ ] MITRE ATT&CK mapping
- [ ] EPSS integration
- [ ] Risk prioritization engine

## Future

- [ ] Interactive Power BI dashboard
- [ ] REST API
- [ ] Azure deployment
- [ ] AI-assisted threat analysis
- [ ] Automated reporting

---

# Future Vision

The long-term goal of SignalIQ is to transform fragmented threat intelligence into contextual and actionable insights.

By combining multiple intelligence sources, enrichment pipelines, automated prioritization, and visualization, SignalIQ aims to help analysts spend less time searching for information and more time making informed security decisions.

---

# License

This project is licensed under the MIT License.