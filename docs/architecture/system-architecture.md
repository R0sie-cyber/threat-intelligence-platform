# System Architecture

## Purpose

Modern security analysts rarely struggle because they lack threat intelligence. They struggle because threat intelligence is fragmented across dozens of disconnected platforms, each presenting information differently.

Investigating a single threat often requires switching between vulnerability databases, threat intelligence feeds, vendor advisories, MITRE ATT&CK documentation, security blogs, and internal telemetry before meaningful analysis can even begin.

The Threat Intelligence Platform is designed to reduce analyst cognitive overload by automatically collecting, enriching, organizing, and prioritizing cyber threat intelligence into a centralized workspace.

Rather than replacing analyst expertise, the platform reduces repetitive manual work so analysts can spend more time investigating threats and making informed security decisions.

## Problem Statement

Modern security teams consume intelligence from dozens of disconnected sources, including CISA advisories, NVD, threat intelligence feeds, vulnerability scanners, SIEM alerts, vendor reports, and MITRE ATT&CK.

Although each source provides valuable information, analysts must manually correlate indicators, vulnerabilities, attacker techniques, and threat context before they can begin investigating.

As the volume of threat intelligence continues to grow, analysts spend increasing amounts of time organizing information rather than responding to threats.

The result is slower investigations, inconsistent prioritization, and increased cognitive fatigue.

## Project Vision

Threat intelligence is only valuable if defenders can understand and act on it quickly.

This platform is designed to transform fragmented threat intelligence into contextual, prioritized, and actionable insights through automation and intuitive visual workflows.

The long-term goal is to help analysts spend less time searching for information and more time making security decisions.

## Research Question

How can security teams reduce analyst cognitive overload by transforming fragmented threat intelligence into contextual, prioritized, and actionable intelligence?

## Design Principles

The Threat Intelligence Platform is built around six engineering principles that guide every design decision.

### 1. Automation First

Routine collection, enrichment, and prioritization tasks should require minimal manual effort so analysts can focus on investigation instead of data gathering.

### 2. Analyst-Centered Design

Every feature should reduce cognitive load by presenting information in a way that is intuitive, visual, and immediately actionable.

### 3. Context Over Volume

More information does not always improve decision making. The platform prioritizes relevant context over displaying every available data point.

### 4. Modular Architecture

Each component performs a single responsibility, allowing the platform to evolve without tightly coupling different services.

### 5. Explainable Intelligence

Threat scores and recommendations should always be transparent so analysts understand why a threat was prioritized.

### 6. Scalable by Design

The platform should support additional threat feeds, enrichment providers, automation workflows, and cloud services without requiring major architectural redesign.

---

## High-Level Architecture

Threat Sources

↓

Collection Layer

↓

Enrichment Layer

↓

Risk Prioritization

↓

Database

↓

REST API

↓

Dashboard

↓
---
# Component Overview

## Threat Reports

### Purpose

Collect raw threat intelligence from trusted public sources.

### Input

External intelligence providers.

### Output

Raw threat intelligence in multiple formats.

### Why Here?

Every investigation begins with data collection. Without reliable intelligence sources, downstream analysis cannot occur.

## Collection Layer

### Purpose

Automatically retrieve threat intelligence from multiple external providers.

### Input

API responses, RSS feeds, and downloadable datasets.

### Output

Raw threat objects awaiting validation.

### Design Decisions

- Python will be used because of its mature cybersecurity ecosystem and API support.
- Each threat feed will operate independently so a failure in one source does not stop the pipeline.
- Failed requests will be logged and retried later.
- Collection modules should remain isolated to simplify future expansion.

## Validation & Normalization

### Purpose

Convert inconsistent threat data into a standardized format.

### Input

Raw threat feed responses.

### Output

Validated threat objects with consistent field names and data structures.

### Why Here?

Threat feeds use different naming conventions and formats. Standardization ensures every downstream component works with predictable data.

## Threat Enrichment

### Purpose

Provide additional context that helps analysts better understand each threat.

### Input

Normalized threat objects.

### Output

Threats enriched with contextual intelligence including:

- MITRE ATT&CK techniques
- EPSS scores
- CVSS scores
- Vendor information
- Exploitation status
- Related Indicators of Compromise (IOCs)

### Design Decisions

Enrichment occurs after normalization to ensure every provider can be processed using a consistent data model.

Threat intelligence should prioritize context rather than simply displaying additional information.

## Risk Prioritization

### Purpose

Reduce analyst cognitive overload by highlighting the threats that deserve immediate attention.

### Input

Enriched threat intelligence.

### Output

Prioritized threats with transparent risk scores.

### Scoring Philosophy

Threats receive higher priority when they:

- Are actively exploited
- Have high EPSS scores
- Have critical CVSS scores
- Map to high-impact MITRE ATT&CK techniques
- Affect widely used software
- Target critical infrastructure

The platform emphasizes explainable prioritization so analysts understand why a threat appears at the top of the dashboard

## Database

### Purpose

Store normalized and enriched threat intelligence for fast retrieval and analysis.

### Planned Tables

- Threats
- Indicators of Compromise
- MITRE Techniques
- Threat Actors
- Collections
- Reports

### Future Tables

- Users
- Saved Investigations
- Analyst Notes

### Relationships

One threat may contain multiple indicators.

One indicator may map to multiple ATT&CK techniques.

One report may reference multiple threats.

## REST API

### Purpose

Expose platform functionality through reusable endpoints.

### Planned Endpoints

GET /threats

GET /threat/{id}

GET /high-risk

GET /statistics

POST /report

### Why Here?

Separating the API from the dashboard allows future integrations with mobile applications, automation tools, and external security platforms.

## Dashboard

### Purpose

Present complex threat intelligence in a way that supports rapid decision making.

### Design Philosophy

The dashboard is designed to reduce information overload by emphasizing clarity, prioritization, and visual context instead of overwhelming analysts with raw data.

### Core Views

Landing Page

- Current threat landscape
- Highest priority threats
- Recent intelligence

Threat Explorer

- Filter by ATT&CK
- Filter by severity
- Filter by CVE
- Search indicators

Threat Details

- MITRE mapping
- IOC relationships
- EPSS
- CVSS
- Recommended mitigations

## Reporting

### Report Types

Technical Investigation Report

Designed for SOC analysts.

Executive Threat Brief

Designed for security leadership.

Weekly Intelligence Summary

Provides a high-level overview of newly collected threats and trends.

## Data Flow

1. Threat intelligence is collected from multiple external providers.
2. Raw data is validated and normalized into a consistent format.
3. Threats are enriched with contextual intelligence including ATT&CK mappings, CVSS, and EPSS.
4. The prioritization engine evaluates each threat and assigns a transparent risk score.
5. Processed intelligence is stored in the platform database.
6. The REST API exposes the processed data.
7. The dashboard presents prioritized intelligence through interactive visualizations.
8. Analysts investigate threats and generate reports directly from the platform.