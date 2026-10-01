CREATE TABLE sftp_accounts (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    password_set INTEGER NOT NULL DEFAULT 0 CHECK (password_set IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX sftp_accounts_site_id ON sftp_accounts(site_id);

CREATE TABLE sftp_keys (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    account_id TEXT NOT NULL REFERENCES sftp_accounts(id) ON DELETE CASCADE,
    key_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (account_id, fingerprint)
);
