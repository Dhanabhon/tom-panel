CREATE TABLE databases (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    suffix TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'deleting')),
    active_generation INTEGER NOT NULL DEFAULT 1,
    password_set INTEGER NOT NULL DEFAULT 0 CHECK (password_set IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (site_id, suffix)
);

CREATE INDEX databases_site_id ON databases(site_id);

CREATE TABLE database_credentials (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 99),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    created_at INTEGER NOT NULL,
    UNIQUE (database_id, generation)
);

CREATE TABLE database_backups (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    agent_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE phpmyadmin_endpoints (
    site_id TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('private', 'public_subdomain', 'public_port')),
    hostname TEXT,
    port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    basic_auth_user TEXT NOT NULL DEFAULT '',
    basic_auth_set INTEGER NOT NULL DEFAULT 0 CHECK (basic_auth_set IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
