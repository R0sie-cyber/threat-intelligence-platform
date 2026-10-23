
# Engineering Journal: EPSS Integration

**Project:** SignalIQ Threat Intelligence Platform  
**Date:** October 23, 2026  
**Milestone:** EPSS Integration and Automated Enrichment

## Objective

Integrate the Exploit Prediction Scoring System (EPSS) into SignalIQ to complement existing CISA Known Exploited Vulnerabilities (KEV) and National Vulnerability Database (NVD) intelligence.

The goal was to retrieve exploitation probability scores, store them reliably, and establish a foundation for explainable vulnerability prioritization.

## Problems Addressed

Before this milestone, SignalIQ stored vulnerability information from CISA KEV and NVD but did not incorporate EPSS probability estimates.

The integration needed to address several engineering requirements:

1. Retrieve EPSS scores for existing CVEs.
2. Store exploitation probability and percentile information.
3. Update previously stored scores without creating duplicate records.
4. Track successful lookups, including CVEs without available scores.
5. Avoid unnecessarily reprocessing previously checked vulnerabilities.
6. Process large datasets in controlled batches.
7. Preserve database integrity during enrichment.

## Engineering Improvements

### EPSS API Integration

Implemented retrieval of EPSS data from the FIRST EPSS API.

The integration extracts:

- CVE identifier
- EPSS probability score
- EPSS percentile
- Score publication date

### Database Schema

Created the `epss_enrichment` table to associate EPSS intelligence with existing vulnerability records.

Added constraints for score ranges, unique threat relationships, and foreign-key references.

Created an index to support queries using EPSS probability.

### Lookup Status Tracking

Created the `epss_lookup_status` table to record whether a successful lookup returned an EPSS score.

The table stores:

- Threat identifier
- Lookup status (`found` or `not_found`)
- Last checked timestamp

This separates unavailable scores from vulnerabilities that have never been checked.

### Database Upserts

Implemented SQLite upserts to update existing EPSS records without introducing duplicates.

Each successful enrichment also records a UTC timestamp indicating when SignalIQ processed the data.

### Batch Enrichment

Implemented batch API retrieval and database persistence.

Added automatic selection of vulnerabilities that have neither EPSS scores nor completed lookup records.

Created a collection workflow that processes up to 50 CVEs per batch, reports progress, and supports resuming after interruptions.

### SQLite Connection Management

Updated EPSS database operations to explicitly close SQLite connections.

This also resolved resource warnings encountered during automated testing on Windows.

## Validation and Testing

- Confirmed 1,653 existing vulnerabilities.
- Confirmed 1,653 NVD enrichment records.
- Retrieved EPSS data from the live FIRST API.
- Tested single-CVE and batch retrieval.
- Verified EPSS upserts update scores without duplicating records.
- Completed initial EPSS enrichment for all 1,653 stored vulnerabilities.
- Reconciled five earlier EPSS records with lookup tracking.
- Confirmed 1,653 EPSS records and 1,653 `found` lookup statuses.
- Confirmed zero unprocessed vulnerabilities.
- Verified database integrity and no foreign-key violations.
- Passed three EPSS automated tests using temporary databases and mocked API responses.
- Passed the complete seven-test project suite.
- Resolved SQLite resource warnings during testing.

## Remaining Considerations

- Implement a periodic EPSS refresh policy because exploitation probabilities change over time.
- Add stronger API response validation and retry handling.
- Expand automated tests for interrupted batches and partial failures.
- Improve observability through structured logging.
- Evaluate historical EPSS trends in a future milestone.

## Outcome

SignalIQ now incorporates CISA KEV, NVD, and EPSS intelligence for its existing vulnerability dataset.

The EPSS pipeline supports retrieval, persistence, controlled batch collection, lookup tracking, and repeatable automated testing.

This milestone establishes the foundation for combining exploitation probability, vulnerability severity, and known exploitation evidence into explainable prioritization logic.
