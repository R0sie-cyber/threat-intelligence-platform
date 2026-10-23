
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    vulnerability_name TEXT NOT NULL,
    date_added TEXT NOT NULL,
    due_date TEXT,
    required_action TEXT,
    known_ransomware_use TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL UNIQUE,

    cvss_score REAL,
    cvss_severity TEXT,
    cwe TEXT,
    published_date TEXT,
    last_modified TEXT,
    description TEXT,

    last_enriched_at TEXT,

    FOREIGN KEY (threat_id)
        REFERENCES threats(id)
);

CREATE INDEX IF NOT EXISTS idx_threat_enrichment_last_enriched
    ON threat_enrichment(last_enriched_at);


-- EPSS enrichment: latest exploitation probability for each vulnerability
CREATE TABLE IF NOT EXISTS epss_enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL UNIQUE,
    epss_score REAL NOT NULL CHECK (epss_score >= 0 AND epss_score <= 1),
    epss_percentile REAL NOT NULL CHECK (epss_percentile >= 0 AND epss_percentile <= 1),
    score_date TEXT NOT NULL,
    last_enriched_at TEXT NOT NULL,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- Support queries using EPSS probability
CREATE INDEX IF NOT EXISTS idx_epss_enrichment_score
ON epss_enrichment(epss_score);


-- Track EPSS lookups, including CVEs without available scores
CREATE TABLE IF NOT EXISTS epss_lookup_status (
    threat_id INTEGER PRIMARY KEY,
    lookup_status TEXT NOT NULL
        CHECK (lookup_status IN ('found', 'not_found')),
    last_checked_at TEXT NOT NULL,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

CREATE INDEX IF NOT EXISTS idx_epss_lookup_status_checked
ON epss_lookup_status(last_checked_at);
