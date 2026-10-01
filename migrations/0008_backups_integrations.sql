-- Rebuild sites with the deletion lifecycle states. FK enforcement is
-- deferred for the transaction: the parent is swapped through sites_new and
-- renamed back, so every child reference keeps resolving to "sites".
PRAGMA defer_foreign_keys=ON;

CREATE TABLE sites_new (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    kind TEXT NOT NULL CHECK (kind IN ('static', 'php', 'reverse_proxy')),
    state TEXT NOT NULL CHECK (state IN ('provisioning', 'active', 'failed', 'disabled', 'deleting', 'quarantined')),
    primary_domain TEXT NOT NULL,
    http_port INTEGER CHECK (http_port IS NULL OR http_port BETWEEN 1 AND 65535),
    https_port INTEGER NOT NULL CHECK (https_port BETWEEN 1 AND 65535),
    php_version TEXT CHECK (php_version IS NULL OR php_version IN ('8.3', '8.4', '8.5')),
    proxy_target TEXT,
    public INTEGER NOT NULL DEFAULT 0 CHECK (public IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT INTO sites_new(id, kind, state, primary_domain, http_port, https_port, php_version, proxy_target, public, created_at, updated_at)
SELECT id, kind, state, primary_domain, http_port, https_port, php_version, proxy_target, public, created_at, updated_at
FROM sites;

DROP TABLE sites;
ALTER TABLE sites_new RENAME TO sites;

CREATE TABLE backups (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('manual', 'scheduled', 'pre_restore', 'final')),
    storage TEXT NOT NULL CHECK (storage IN ('local', 's3', 'local+s3')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'failed', 'restoring')),
    agent_path TEXT,
    object_key TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    manifest BLOB NOT NULL DEFAULT '{}',
    protected INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);

CREATE INDEX backups_site_id ON backups(site_id);
CREATE INDEX backups_schedule ON backups(site_id, kind, created_at);

CREATE TABLE site_quarantine (
    site_id TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    data_path TEXT NOT NULL,
    quarantined_at INTEGER NOT NULL,
    purges_at INTEGER NOT NULL
);

CREATE TABLE integrations (
    provider TEXT PRIMARY KEY CHECK (provider IN ('s3', 'smtp')),
    config_json TEXT NOT NULL DEFAULT '{}',
    secret_ciphertext BLOB,
    updated_at INTEGER NOT NULL
);
