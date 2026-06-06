CREATE TABLE IF NOT EXISTS cve (
    id          SERIAL PRIMARY KEY,
    cve_id      TEXT NOT NULL UNIQUE,
    title       TEXT,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_nvd (
    id              SERIAL PRIMARY KEY,
    cve_id_ref      INT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    source_cve_id   TEXT,
    summary         TEXT,
    published_date  DATE,
    last_modified   TIMESTAMP WITH TIME ZONE,
    source_url      TEXT,
    raw_json        JSONB,
    ingested_at     TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_rhel (
    id              SERIAL PRIMARY KEY,
    cve_id_ref      INT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    advisory_name   TEXT,
    summary         TEXT,
    severity        TEXT,
    published_date  DATE,
    source_url      TEXT,
    raw_json        JSONB,
    ingested_at     TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_mitre (
    id              SERIAL PRIMARY KEY,
    cve_id_ref      INT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    description     TEXT,
    assigner        TEXT,
    published_date  DATE,
    source_url      TEXT,
    raw_json        JSONB,
    ingested_at     TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_github (
    id              SERIAL PRIMARY KEY,
    cve_id_ref      INT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
    gh_advisory_id  TEXT,
    summary         TEXT,
    ecosystem       TEXT,
    published_date  DATE,
    source_url      TEXT,
    raw_json        JSONB,
    ingested_at     TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cvss_score (
    id                  SERIAL PRIMARY KEY,
    source_name         TEXT NOT NULL CHECK (source_name IN ('nvd','rhel','mitre','github')),
    source_entry_id     INT NOT NULL,  
    version             TEXT NOT NULL,  
    vector              TEXT NOT NULL,
    score               NUMERIC(3,1) NOT NULL CHECK (score >= 0 AND score <= 10),
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE (source_name, source_entry_id, version)
);

CREATE TABLE IF NOT EXISTS reference (
    id                  SERIAL PRIMARY KEY,
    cve_id_ref          INT REFERENCES cve(id) ON DELETE CASCADE,
    source_name         TEXT CHECK (source_name IN ('nvd','rhel','mitre','github')),
    source_entry_id     INT,
    url                 TEXT NOT NULL,
    note                TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_cveid ON cve(cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_cve_ref ON cve_nvd(cve_id_ref);
CREATE INDEX IF NOT EXISTS idx_rhel_cve_ref ON cve_rhel(cve_id_ref);
CREATE INDEX IF NOT EXISTS idx_mitre_cve_ref ON cve_mitre(cve_id_ref);
CREATE INDEX IF NOT EXISTS idx_github_cve_ref ON cve_github(cve_id_ref);
CREATE INDEX IF NOT EXISTS idx_cvss_source ON cvss_score(source_name, source_entry_id);
CREATE INDEX IF NOT EXISTS idx_ref_cve ON reference(cve_id_ref);
