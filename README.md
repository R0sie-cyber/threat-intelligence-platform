# Threat Intelligence Platform

> **SignalIQ** is the current development codename for this project. The final platform name is still being evaluated.

An end-to-end threat intelligence platform that automates the collection, enrichment, prioritization, and visualization of cyber threat intelligence to reduce analyst cognitive overload.

---

## Overview

Modern security analysts rely on dozens of disconnected intelligence sources to investigate a single threat. Valuable context is scattered across vulnerability databases, threat feeds, vendor advisories, MITRE ATT&CK documentation, and security blogs, forcing analysts to manually collect and correlate information before meaningful investigation can begin.

The Threat Intelligence Platform is being developed to reduce analyst cognitive overload by automatically collecting, enriching, prioritizing, and organizing cyber threat intelligence into a centralized workflow.

This project demonstrates software engineering, cybersecurity, and threat intelligence concepts while following a modular architecture designed for future cloud deployment.

---

## Why I Built This

While working through threat hunting labs and vulnerability research, I realized analysts often have to switch between multiple intelligence sources to investigate a single vulnerability.

I'm building this project to better understand how modern threat intelligence platforms are designed and to explore how threat collection, enrichment, and prioritization can be automated using Python, public threat feeds, cloud technologies, and data visualization.

Rather than replacing analysts, the goal is to reduce repetitive data gathering so more time can be spent investigating and understanding threats.

---

## Current Features

- Collects live threat intelligence from the CISA Known Exploited Vulnerabilities (KEV) feed
- Validates API responses before processing
- Stores raw threat intelligence for future enrichment
- Modular service-oriented architecture
- Architecture and system design documentation
- Database schema design

---

## Planned Features

- MITRE ATT&CK technique mapping
- CVE enrichment
- EPSS integration
- Risk prioritization engine
- Interactive Power BI dashboard
- REST API
- Azure deployment
- Automated analyst reporting
- Multi-source threat intelligence collection

---

## System Architecture

```
Threat Sources
      │
      ▼
Collection Layer
      │
      ▼
Validation
      │
      ▼
Raw Threat Storage
      │
      ▼
Future Modules
      │
      ├── Threat Enrichment
      ├── Risk Prioritization
      ├── Database
      ├── REST API
      └── Interactive Dashboard
```

Detailed architecture documentation is available in:

```
docs/architecture/system-architecture.md
```

---

## Tech Stack

### Languages
- Python

### Threat Intelligence
- CISA Known Exploited Vulnerabilities (KEV)
- REST APIs

### Cybersecurity Concepts
- Threat Intelligence
- MITRE ATT&CK
- Vulnerability Management

### Planned Technologies
- Microsoft Azure
- Power BI
- SQL Database

---

## Repository Structure

```
threat-intelligence-platform/
│
├── docs/
│   └── architecture/
│       ├── system-architecture.md
│       └── data-sources.md
│
├── src/
│   ├── collection/
│   │   └── cisa_collector.py
│   └── database/
│       └── schema.md
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/R0sie-cyber/threat-intelligence-platform.git
```

Navigate into the project

```bash
cd threat-intelligence-platform
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate the environment

Windows

```bash
.venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

Collect the latest CISA Known Exploited Vulnerabilities (KEV) feed.

```bash
python src/collection/cisa_collector.py
```

Example output

```
======================================
 SignalIQ Threat Collection
======================================

Connecting to CISA KEV feed...

Collection Summary

Threat Feed:
CISA Known Exploited Vulnerabilities

Vulnerabilities:
1631

Collection completed successfully.
```

---

## Development Roadmap

- [x] Repository setup
- [x] Project architecture
- [x] Documentation
- [x] Database schema
- [x] Initial CISA KEV collector
- [ ] Data normalization
- [ ] Threat enrichment
- [ ] MITRE ATT&CK mapping
- [ ] Risk prioritization
- [ ] Database implementation
- [ ] REST API
- [ ] Interactive dashboard
- [ ] Azure deployment

---

## Future Improvements

- Support multiple threat intelligence providers
- Implement automated enrichment workflows
- Integrate EPSS and CVSS scoring
- Build analyst investigation dashboard
- Generate executive threat reports
- Deploy platform to Microsoft Azure

---

## License

This project is licensed under the MIT License.
