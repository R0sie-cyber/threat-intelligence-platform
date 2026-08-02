# SignalIQ Data Flow

## Overview

SignalIQ follows a multi-stage pipeline that transforms raw vulnerability data into structured threat intelligence.

Each stage has a single responsibility, making the platform easier to maintain, extend, and debug.

---

## Current Data Flow

```text
CISA KEV Feed
        │
        ▼
Collection Layer
        │
        ▼
SQLite Database (Threats)
        │
        ▼
NVD Enrichment
        │
        ▼
SQLite Database (Threat Enrichment)
```

---

## Future Data Flow

```text
CISA KEV Feed
        │
        ▼
Collection Layer
        │
        ▼
Validation & Normalization
        │
        ▼
Threat Database
        │
        ▼
NVD Enrichment
        │
        ▼
MITRE ATT&CK Enrichment
        │
        ▼
EPSS Enrichment
        │
        ▼
Risk Prioritization Engine
        │
        ▼
REST API
        │
        ▼
Power BI Dashboard
```

---

## Pipeline Stages

### 1. Collection

Retrieve vulnerability information from trusted public threat intelligence sources.

### 2. Storage

Store collected vulnerabilities in a normalized SQLite database.

### 3. Enrichment

Augment vulnerabilities with additional technical context from external sources such as the National Vulnerability Database (NVD).

### 4. Prioritization *(Planned)*

Calculate transparent risk scores using enrichment data from multiple intelligence sources.

### 5. Visualization *(Planned)*

Present prioritized threat intelligence through an interactive Power BI dashboard to support analyst decision-making.