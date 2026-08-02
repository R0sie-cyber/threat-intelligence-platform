# Separating Collection from Enrichment

**Date:** July 27 - July 30, 2026

## Milestone

Normalized the database.

## What Sparked This?

At first, I thought I could just keep adding more columns to the `threats` table. But the more I thought about it, the more I realized I was mixing two completely different types of information.

The CISA data represented the original threat I collected.

The NVD data would be additional context added later.

Once I realized that, separating them into different tables felt like the better long-term design.

## What I Built

- Created the `threat_enrichment` table.
- Added a foreign key relationship.
- Added a `UNIQUE(threat_id)` constraint.

## My Thought Process

Instead of putting everything into one large table, I separated threat collection from threat enrichment.

That made the database much more flexible because I could continue adding enrichment from other intelligence sources later without constantly changing the original threat records.

I also wanted the database itself to help enforce my design. By making `threat_id` unique, each threat could only have one enrichment record. Instead of relying on my Python code to remember that rule, SQLite would enforce it automatically.

## Biggest Takeaway

This was probably the first time I really started thinking like a data engineer instead of just a Python programmer. The database wasn't just storing data anymore—it was helping enforce how the application should behave.

## Next Goal

Connect SignalIQ to the National Vulnerability Database (NVD).