
# Engineering Journal: NVD Pipeline Improvements

**Project:** SignalIQ Threat Intelligence Platform  
**Date:** October 22, 2026  
**Milestone:** Backend Reliability and Incremental Enrichment

## Objective

Improve the existing NVD enrichment pipeline to reduce unnecessary API requests, support controlled vulnerability refreshes, and handle temporary API failures more reliably.

The goal of this milestone was to strengthen SignalIQ's existing backend architecture before introducing additional threat intelligence sources and risk prioritization capabilities.

## Problems Identified

During a review of the original NVD enrichment implementation, three limitations were identified:

1. **Unnecessary API requests:** Every execution processed all 1,653 stored CVEs, regardless of whether enrichment data already existed. This increased execution time and the likelihood of encountering NVD API rate limits.

2. **Outdated enrichment records:** The database used `INSERT OR IGNORE`, which prevented existing vulnerability records from receiving updated NVD information.

3. **Unnecessary retries:** The API request function retried all request failures without distinguishing temporary errors from permanent failures.

These limitations highlighted the need for a more efficient and maintainable enrichment process.

## Engineering Improvements

### 1. Incremental Enrichment

Updated the enrichment pipeline to support four processing modes:

- **New:** Retrieves vulnerabilities that do not have existing enrichment records.
- **Stale:** Selects previously enriched vulnerabilities whose refresh timestamps exceed a configurable interval.
- **Legacy:** Selects existing enrichment records without refresh timestamps.
- **Force:** Allows a specific CVE to be selected for manual refresh regardless of its current status.

The default execution mode now processes only newly discovered vulnerabilities.

This prevents unnecessary API requests while preserving the ability to refresh previously collected intelligence.

### 2. Refresh Tracking

Added a `last_enriched_at` column to the `threat_enrichment` table.

This field records the UTC timestamp when SignalIQ successfully retrieves and processes vulnerability information from NVD.

The timestamp is maintained separately from NVD's `lastModified` field:

- `lastModified` identifies when NVD last modified the vulnerability record.
- `last_enriched_at` identifies when SignalIQ last successfully processed the vulnerability.

This distinction supports configurable refresh intervals and future automation.

Existing enrichment records were preserved during the database migration. Legacy records without timestamps can be refreshed in controlled batches rather than reprocessed simultaneously.

### 3. SQLite Upserts

Replaced `INSERT OR IGNORE` with SQLite's `ON CONFLICT DO UPDATE` functionality.

The updated implementation allows existing enrichment records to receive new vulnerability information without creating duplicate entries.

Used `COALESCE` to preserve existing field values when newly retrieved enrichment fields are null.

This approach supports incremental updates while reducing the risk of losing previously stored information during incomplete refreshes.

### 4. Selective API Retries

Improved the NVD request function to distinguish between temporary and permanent failures.

Retryable conditions include:

- HTTP 429: Too Many Requests
- HTTP 500: Internal Server Error
- HTTP 502: Bad Gateway
- HTTP 503: Service Unavailable
- HTTP 504: Gateway Timeout
- Temporary network connection failures
- Request timeouts

Implemented exponential backoff with randomized delays and support for numeric `Retry-After` headers.

Permanent HTTP failures, such as HTTP 404, now fail immediately instead of triggering unnecessary retries.

### 5. Database Integrity

Updated the shared database connection function to enable SQLite foreign-key enforcement.

This helps prevent invalid relationships between the `threats` and `threat_enrichment` tables for operations performed through the shared connection function.

Also introduced an index on `last_enriched_at` to support future timestamp-based refresh queries.

## Validation and Testing

### Database Verification

Before modifying the enrichment pipeline, verified the existing SQLite database.

Results:

- Total stored vulnerabilities: 1,653
- Total enrichment records: 1,653
- Distinct enriched threats: 1,653
- Threats without enrichment: 0
- Enrichment records missing CVSS scores: 0
- Enrichment records missing descriptions: 0

After applying the schema migration, verified:

- The `last_enriched_at` column exists.
- All 1,653 vulnerability records remain intact.
- All 1,653 enrichment records remain intact.
- SQLite integrity check returned `ok`.

### Incremental and Refresh Selection Testing

Tested the different enrichment selection modes.

Initial results:

- New vulnerabilities selected: 0
- Stale vulnerabilities selected: 0
- Legacy vulnerabilities selected with a limit of 3: 3

After refreshing one legacy vulnerability, additional selection tests confirmed:

- Manual selection successfully identified the specified CVE.
- A seven-day refresh interval excluded the recently refreshed record.
- A zero-day refresh interval selected the recently refreshed record.
- Legacy selection continued identifying records without refresh timestamps.

These tests confirmed the expected selection behavior for the scenarios evaluated.

### Live NVD Refresh

Successfully executed a controlled refresh of `CVE-2026-16232` using the NVD API.

Results:

- Selected vulnerabilities: 1
- Successful refreshes: 1
- Failed refreshes: 0
- CVSS score: 9.8
- Severity: CRITICAL
- Total enrichment records after refresh: 1,653
- Records with refresh timestamps: 1

The existing enrichment record was updated without creating a duplicate.

The test also confirmed that NVD's `lastModified` value remained separate from SignalIQ's new `last_enriched_at` timestamp.

### Automated Unit Testing

Created two new test files:

- `tests/test_nvd_retries.py`
- `tests/test_nvd_upsert.py`

The retry tests used mocked HTTP responses to verify:

1. HTTP 404 failures do not trigger retries.
2. HTTP 503 failures trigger retries and can recover successfully.
3. Temporary connection failures trigger retries and can recover successfully.

The upsert test used a temporary SQLite database to verify:

4. Existing enrichment values are preserved when refreshed fields are null, while valid updated fields are stored without creating duplicate records.

Executed the complete discoverable test suite using:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Results:

- Tests executed: 4
- Tests passed: 4
- Tests failed: 0

All four automated tests passed.

## Engineering Decisions and Rationale

### Why Incremental Enrichment?

Repeatedly requesting information for every stored vulnerability wastes API requests and increases processing time.

Incremental enrichment allows SignalIQ to prioritize new or outdated records while reducing unnecessary network traffic.

### Why Preserve Periodic Refreshes?

Vulnerability intelligence changes over time. NVD may update descriptions, severity information, or other vulnerability metadata.

Permanently skipping previously enriched vulnerabilities would eventually produce outdated intelligence.

A configurable refresh strategy balances data freshness with API efficiency.

### Why Separate Legacy Records?

Existing enrichment records were created before refresh tracking was introduced.

Rather than assigning inaccurate timestamps or immediately refreshing all 1,653 records, SignalIQ identifies these records separately and supports controlled batch processing.

### Why Use Upserts?

An enrichment platform must support both inserting new information and updating previously stored intelligence.

Upserts allow SignalIQ to maintain a single enrichment record per vulnerability while incorporating new information as it becomes available.

### Why Test with Mocked Requests?

Mocked HTTP responses allow API failure scenarios to be tested consistently without relying on actual service outages or consuming NVD API requests.

Temporary SQLite databases also allow database update behavior to be tested without modifying production project data.

## Remaining Considerations

Although the core improvements have been implemented and tested, several enhancements remain:

- Implement automated scheduling to trigger periodic refresh execution.
- Expand automated tests for batch processing, unsuccessful refreshes, and timestamp handling.
- Verify the complete manual refresh workflow beyond record selection.
- Review NVD API rate limits and refine request pacing as needed.
- Improve validation of incomplete or inconsistent API responses.
- Evaluate whether refreshes should distinguish unavailable fields from fields intentionally removed by NVD.
- Add additional database relationship and foreign-key enforcement tests.
- Consider more advanced refresh strategies based on NVD modification activity.

## Outcome

SignalIQ now supports incremental NVD enrichment, controlled refresh selection, updates to existing vulnerability records, selective API retries, and successful enrichment timestamps.

The updated pipeline was validated through database integrity checks, a successful live NVD refresh, and four passing automated unit tests.

These improvements strengthen SignalIQ's backend reliability and establish a more maintainable foundation for future intelligence integrations.

## Next Milestone

**EPSS Integration and Exploitation Probability Enrichment**

The next development milestone will focus on integrating the Exploit Prediction Scoring System (EPSS) to provide additional vulnerability prioritization context.

Planned objectives include:

1. Retrieve EPSS probability and percentile information for stored CVEs.
2. Design database storage for EPSS enrichment.
3. Implement efficient collection and update workflows.
4. Validate API responses and handle missing EPSS records.
5. Create automated tests for EPSS collection and persistence.
6. Prepare EPSS data for integration into SignalIQ's future risk prioritization engine.

This milestone will bring SignalIQ closer to its central objective: transforming fragmented vulnerability intelligence into contextual, prioritized, and actionable insights.
