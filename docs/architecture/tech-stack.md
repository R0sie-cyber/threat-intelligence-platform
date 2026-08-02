# Technology Stack

## Overview

SignalIQ is built using technologies selected to support a modular threat intelligence pipeline.

The goal of the technology choices is not to use the newest tools available, but to select tools that are practical, maintainable, and appropriate for building a cybersecurity data platform.

---

# Programming Language

## Python

### Purpose

Python is the primary programming language used to build SignalIQ's collection, database, and enrichment workflows.

### Why Python?

Python was selected because it provides strong support for:

- REST API integrations
- JSON data processing
- Automation workflows
- Cybersecurity tooling
- Data analysis

Python also has a large cybersecurity ecosystem, making it commonly used for security automation and threat intelligence tasks.

### Current Usage

Python is currently used for:

- Collecting vulnerability data from CISA
- Processing API responses
- Connecting to SQLite
- Running enrichment pipelines
- Transforming threat intelligence data

---

# Database

## SQLite

### Purpose

SQLite provides persistent storage for collected and enriched threat intelligence.

### Why SQLite?

SQLite was chosen because it is:

- Lightweight
- Portable
- Easy to configure
- Serverless
- Well suited for local development and prototyping

Since SignalIQ is currently being developed as a local application, SQLite provides the necessary database functionality without introducing unnecessary infrastructure complexity.

### Current Usage

SQLite stores:

- Threat records
- Vulnerability metadata
- Enrichment information
- Relationships between collected and enriched data

---

# Data Formats

## JSON

### Purpose

JSON is the primary format used for exchanging threat intelligence data through APIs.

### Current Usage

SignalIQ processes JSON responses from:

- CISA Known Exploited Vulnerabilities (KEV)
- National Vulnerability Database (NVD)

The application extracts relevant fields from API responses and transforms them into structured database records.

---

# APIs

## REST APIs

### Purpose

REST APIs allow SignalIQ to collect threat intelligence from external providers.

### Current Usage

SignalIQ currently integrates with:

- CISA KEV API
- NVD API

Future versions will expand support for additional intelligence providers.

---

# Version Control

## Git and GitHub

### Purpose

Git is used to track development changes and maintain project history.

### Why Git?

Version control allows:

- Tracking engineering decisions
- Recovering previous versions
- Documenting project evolution
- Sharing the project publicly

---

# Documentation

## Markdown

### Purpose

Markdown is used to document architecture, engineering decisions, and project progress.

### Current Documentation Includes

- System architecture
- Data sources
- Engineering journal
- Roadmap documentation

---

# Planned Technologies

## Microsoft Azure

### Purpose

Future cloud deployment and scalability.

Potential uses include:

- Hosting application services
- Cloud databases
- Automated workflows
- Security monitoring integrations

---

## Power BI

### Purpose

Future visualization and analyst dashboard.

Potential capabilities include:

- Threat trends
- Vulnerability analysis
- Risk prioritization views
- Executive reporting

---

## AI and Machine Learning

### Purpose

Future intelligence assistance features.

Potential applications include:

- Automated threat summaries
- Natural language search
- Investigation assistance
- Trend analysis