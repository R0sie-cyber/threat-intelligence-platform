# Building My First Enrichment Pipeline

**Date:** July 30 - August 1, 2026

## Milestone

Integrated the National Vulnerability Database (NVD).

## What Sparked This?

Once the CISA data was stored, I realized something.

CISA tells me **which** vulnerabilities are actively being exploited, but it doesn't tell me much about the vulnerabilities themselves.

If I wanted SignalIQ to eventually prioritize threats instead of just collecting them, I needed more context.

That's what led me to the NVD API.

## What I Built

- Built an NVD API client.
- Retrieved vulnerability information using stored CVE IDs.
- Parsed nested JSON responses.
- Extracted:
  - CVSS score
  - CVSS severity
  - CWE
  - Description
  - Published date
  - Last modified date
- Stored enrichment data in the `threat_enrichment` table.
- Successfully enriched more than 1,600 vulnerabilities.

## My Thought Process

At first, I assumed this would be another straightforward API integration.

Then I looked at the NVD response.

The JSON was much more deeply nested than I expected, so instead of storing the entire response, I started thinking about which pieces of information would actually be useful later. I decided to extract only the fields I knew I'd need for future analysis.

While testing, I also realized that not every vulnerability used the same CVSS version. Some used CVSS v3.1, others used v3.0, and older vulnerabilities still used v2. Instead of assuming every response would look the same, I updated the parser to support multiple versions so the pipeline would work across a much wider range of CVEs.

During the full enrichment run, I also ran into API rate limits, temporary service interruptions, and one unexpected mistake—I accidentally closed VS Code while the pipeline was still running.

Thankfully, because I'd already designed the database using `UNIQUE(threat_id)` together with `INSERT OR IGNORE`, I didn't have to start over from the beginning. I simply reran the pipeline, and it automatically skipped anything that had already been enriched.

Looking back, that was one of those moments where an earlier design decision ended up saving me hours of work.

## Biggest Takeaway

This milestone taught me that building against real-world APIs is very different from building small classroom projects. APIs change, data isn't always consistent, requests can fail, and long-running jobs can be interrupted. Thinking about those situations ahead of time makes your software much more reliable.

## Next Goal

Continue expanding SignalIQ by integrating additional threat intelligence sources like MITRE ATT&CK and EPSS. Once those are in place, build a risk prioritization engine before bringing everything together in a Power BI dashboard.