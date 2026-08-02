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

    FOREIGN KEY (threat_id)
        REFERENCES threats(id)
);