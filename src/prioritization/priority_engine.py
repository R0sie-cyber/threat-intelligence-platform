
"""
SignalIQ Explainable Vulnerability Prioritization Engine.

Assigns transparent priority tiers to vulnerabilities using:
- CISA KEV membership
- Known ransomware exploitation
- EPSS exploitation probability
- CVSS technical severity

Priority tiers are SignalIQ heuristics, not official
CISA, FIRST, or NIST classifications.
"""

import argparse
import sqlite3
from contextlib import closing


PRIORITY_LABELS = {
    1: "P1 - Immediate review",
    2: "P2 - High",
    3: "P3 - Elevated",
    4: "P4 - Baseline KEV",
}


def classify_vulnerability(
    cvss_score,
    epss_score,
    known_ransomware_use,
):
    """
    Assign a priority tier and provide supporting reasons.

    All vulnerabilities currently evaluated by SignalIQ
    originate from the CISA KEV catalog.
    """
    cvss = float(cvss_score) if cvss_score is not None else None
    epss = float(epss_score) if epss_score is not None else None

    ransomware_known = (
        str(known_ransomware_use).strip().lower() == "known"
    )

    reasons = ["Listed in CISA KEV (known exploited vulnerability)"]

    if ransomware_known:
        reasons.append("CISA identifies known ransomware use")

    if epss is not None:
        reasons.append(
            f"EPSS exploitation probability: {epss:.2%}"
        )
    else:
        reasons.append("EPSS score unavailable")

    if cvss is not None:
        reasons.append(f"CVSS severity score: {cvss:.1f}/10")
    else:
        reasons.append("CVSS score unavailable")

    if ransomware_known or (
        epss is not None
        and cvss is not None
        and epss >= 0.70
        and cvss >= 9.0
    ):
        priority = 1

    elif (
        (epss is not None and epss >= 0.70)
        or (
            epss is not None
            and cvss is not None
            and epss >= 0.30
            and cvss >= 7.0
        )
    ):
        priority = 2

    elif (
        (epss is not None and epss >= 0.10)
        or (cvss is not None and cvss >= 7.0)
    ):
        priority = 3

    else:
        priority = 4

    return {
        "priority": priority,
        "priority_label": PRIORITY_LABELS[priority],
        "reasons": reasons,
    }


def rank_vulnerabilities(db_path="signaliq.db", limit=10):
    """
    Retrieve and rank vulnerabilities using existing SQLite data.

    Ranking order:
    1. Priority tier
    2. Known ransomware use
    3. EPSS score
    4. CVSS score
    5. CVE identifier
    """
    if limit < 1:
        raise ValueError("Limit must be at least 1.")

    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                t.cve_id,
                t.vendor,
                t.product,
                t.known_ransomware_use,
                t.due_date,
                t.required_action,
                n.cvss_score,
                n.cvss_severity,
                e.epss_score,
                e.epss_percentile,
                e.score_date
            FROM threats AS t
            LEFT JOIN threat_enrichment AS n
                ON t.id = n.threat_id
            LEFT JOIN epss_enrichment AS e
                ON t.id = e.threat_id
            """
        ).fetchall()

    ranked = []

    for row in rows:
        item = dict(row)

        classification = classify_vulnerability(
            item["cvss_score"],
            item["epss_score"],
            item["known_ransomware_use"],
        )

        item.update(classification)
        ranked.append(item)

    ranked.sort(
        key=lambda item: (
            item["priority"],
            -int(
                str(item["known_ransomware_use"]).strip().lower()
                == "known"
            ),
            -(
                item["epss_score"]
                if item["epss_score"] is not None
                else -1
            ),
            -(
                item["cvss_score"]
                if item["cvss_score"] is not None
                else -1
            ),
            item["cve_id"],
        )
    )

    return ranked[:limit]


def display_rankings(vulnerabilities):
    """Print ranked vulnerabilities and their explanations."""
    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    print("\nSIGNALIQ VULNERABILITY PRIORITIZATION")
    print("=" * 55)

    for index, item in enumerate(vulnerabilities, start=1):
        print(f"\n{index}. {item['cve_id']}")
        print(f"   Priority: {item['priority_label']}")
        print(f"   Vendor: {item['vendor']}")
        print(f"   Product: {item['product']}")

        for reason in item["reasons"]:
            print(f"   - {reason}")

        if item["due_date"]:
            print(
                f"   CISA KEV due date: {item['due_date']}"
            )

    print("\nNote: Priorities are SignalIQ heuristics.")
    print(
        "Actual remediation decisions also require asset exposure, "
        "business impact, and operational context."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Rank vulnerabilities using SignalIQ intelligence."
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of ranked vulnerabilities to display.",
    )

    parser.add_argument(
        "--db",
        default="signaliq.db",
        help="Path to the SignalIQ SQLite database.",
    )

    args = parser.parse_args()

    vulnerabilities = rank_vulnerabilities(
        db_path=args.db,
        limit=args.limit,
    )

    display_rankings(vulnerabilities)


if __name__ == "__main__":
    main()
