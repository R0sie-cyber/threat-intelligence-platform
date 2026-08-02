# Collecting Threat Intelligence

**Date:** July 24 - July 27, 2026

## Milestone

Integrated the CISA Known Exploited Vulnerabilities (KEV) feed.

## What Sparked This?

Now that the database was ready, I finally had somewhere to store real threat intelligence. Instead of manually entering vulnerabilities, I wanted SignalIQ to automatically collect data from a trusted source.

## What I Built

- Connected to the CISA KEV API.
- Retrieved vulnerability data.
- Parsed JSON responses.
- Inserted vulnerabilities into SQLite.
- Prevented duplicate threat records.

## My Thought Process

I chose the CISA KEV catalog because it focuses on vulnerabilities that are actually being exploited in the real world. Thousands of CVEs are published every year, but not all of them are actively targeted. Starting with KEV meant SignalIQ was collecting vulnerabilities that security teams should care about first.

As I built the pipeline, I also realized that if I ever ran it more than once, I didn't want duplicate vulnerabilities filling the database. That made me start thinking beyond simply collecting data and toward building a pipeline that could safely run multiple times without creating problems.

## Biggest Takeaway

Working with APIs isn't just about retrieving data. You also have to think about validating it, cleaning it, and making sure your application behaves correctly every time it runs.

## Next Goal

Restructure the database so it can support enrichment from additional threat intelligence sources.