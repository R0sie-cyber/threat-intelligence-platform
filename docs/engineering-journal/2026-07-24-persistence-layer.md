# Building the Database

**Date:** July 5 - July 24, 2026

## Milestone

Built the persistence layer using SQLite.

## What Sparked This?

Once I started thinking about collecting threat intelligence, I realized I didn't want SignalIQ calling an API every single time it needed information. If I wanted the project to eventually combine information from multiple sources, I first needed somewhere to permanently store everything.

## What I Built

- Created the SQLite database.
- Built the `threats` table.
- Created reusable database connection functions.
- Added schema creation scripts.
- Connected Python to SQLite.

## My Thought Process

I chose SQLite because it was simple to set up and didn't require installing or managing a separate database server. Since SignalIQ is still being developed locally, it gave me everything I needed without adding unnecessary complexity.

I also decided to keep my SQL separate from my Python code. At first it felt like extra work, but I knew it would make future schema changes much easier to manage as the project grew.

Another decision I made was to store the data instead of requesting it every time the application ran. That way, future features could build on a consistent dataset instead of depending on live API responses.

## Biggest Takeaway

Before I could analyze threat intelligence, I first needed a reliable place to store it. Building the database made SignalIQ feel like a real application instead of just another API script.

## Next Goal

Populate the database using the CISA Known Exploited Vulnerabilities (KEV) feed.