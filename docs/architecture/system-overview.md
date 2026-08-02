# SignalIQ System Overview

## What is SignalIQ?

SignalIQ is a threat intelligence platform that helps security analysts reduce the time spent gathering and organizing vulnerability information.

Instead of requiring analysts to switch between multiple intelligence sources, SignalIQ collects, enriches, and stores threat data in a centralized database. By bringing together information from trusted public sources, the platform provides additional context that supports faster investigation and more informed security decisions.

The long-term vision is to transform fragmented threat intelligence into contextual, prioritized, and actionable insights through automation.

---

## The Problem

Security analysts rely on many different sources to investigate vulnerabilities, including:

- CISA Known Exploited Vulnerabilities (KEV)
- National Vulnerability Database (NVD)
- MITRE ATT&CK
- EPSS
- Vendor security advisories
- Internal security tools

Each source provides valuable information, but analysts often spend significant time switching between platforms and manually connecting the pieces before they can begin investigating.

As the volume of threat intelligence continues to grow, this fragmented workflow increases cognitive load and slows response times.

---

## The Solution

SignalIQ simplifies that workflow by creating a single pipeline that:

1. Collects vulnerability data from trusted public sources.
2. Stores threat intelligence in a normalized relational database.
3. Enriches vulnerabilities with additional technical context.
4. Prioritizes threats using multiple intelligence sources *(planned)*.
5. Presents actionable insights through an interactive dashboard *(planned)*.

Rather than replacing analyst expertise, SignalIQ automates repetitive data collection and organization so analysts can focus on investigation and decision-making.

---

## Current Capabilities

Version 1 currently supports:

- Collecting vulnerabilities from the CISA Known Exploited Vulnerabilities (KEV) catalog.
- Storing collected vulnerabilities in a normalized SQLite database.
- Enriching vulnerabilities using the National Vulnerability Database (NVD).
- Preventing duplicate records through database constraints.
- Modular Python architecture for future expansion.

---

## Future Vision

Future versions of SignalIQ will continue expanding the platform by integrating additional threat intelligence sources and analytics, including:

- MITRE ATT&CK mappings
- EPSS scores
- Risk prioritization engine
- Power BI dashboard
- AI-assisted threat summaries
- Cloud deployment on Microsoft Azure

---

## Technology Stack

- **Language:** Python
- **Database:** SQLite
- **Data Sources:** CISA KEV, NVD
- **Visualization:** Power BI *(planned)*
- **Cloud:** Microsoft Azure *(planned)*