# Project Foundation

**Date:** July 4, 2026

## Milestone

Started building SignalIQ and planned out the overall architecture.

## What Sparked This?

Looking back, SignalIQ wasn't a project I planned from the beginning. It really evolved from a series of smaller projects and questions I kept asking myself.

It started with my Threat Hunting class, where I spent the semester researching vulnerabilities and writing reports. After turning my capstone into a Power BI dashboard and later deploying it with Azure Static Web Apps, I realized I enjoyed building things that solved real problems instead of just completing assignments.

Around that same time, I joined the Break Through Tech AI Program through Cornell Tech. It challenged me to think about what kind of long-term project I wanted to build. Instead of creating a brand-new project every time I learned a new technology, I wanted one project that could continue growing alongside my skills.

That's really where the idea for SignalIQ began.

## What I Built

- Set up the project structure.
- Created a Python virtual environment.
- Initialized Git and GitHub.
- Organized the project into separate modules.
- Planned out the first version of the roadmap.

## My Thought Process

One of the first decisions I made was not to put everything into one Python file. It probably would've been faster at the beginning, but I knew that if I wanted this project to grow over time, it would become difficult to manage.

Instead, I separated different responsibilities into their own modules, like the database, collectors, and enrichment pipeline. Even though there wasn't much code yet, I wanted the project to have a structure that I could continue building on instead of constantly reorganizing later.

I also chose Python because it already has great support for working with APIs, JSON, databases, and cybersecurity tools, so it felt like the right language for the type of project I wanted to build.

## Biggest Takeaway

I realized that good software doesn't start with features—it starts with a solid foundation. Spending time on the architecture now would make adding future features much easier.

## Next Goal

- Build the database.
- Start collecting vulnerability data from CISA.