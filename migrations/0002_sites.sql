CREATE TABLE sites (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    kind TEXT NOT NULL CHECK (kind IN ('static', 'php', 'reverse_proxy')),
    state TEXT NOT NULL CHECK (state IN ('provisioning', 'active', 'failed', 'disabled')),
    primary_domain TEXT NOT NULL,
    http_port INTEGER CHECK (http_port IS NULL OR http_port BETWEEN 1 AND 65535),
    https_port INTEGER NOT NULL CHECK (https_port BETWEEN 1 AND 65535),
    php_version TEXT CHECK (php_version IS NULL OR php_version IN ('8.3', '8.4', '8.5')),
    proxy_target TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE domains (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    kind TEXT NOT NULL CHECK (kind IN ('primary', 'subdomain', 'parked', 'redirect')),
    redirect_target TEXT,
    managed INTEGER NOT NULL DEFAULT 1 CHECK (managed IN (0, 1)),
    provider_record_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (hostname, port)
);

CREATE INDEX domains_site_id ON domains(site_id);
CREATE UNIQUE INDEX domains_provider_record ON domains(provider_record_id) WHERE provider_record_id IS NOT NULL;

CREATE TABLE certificates (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    hostname_set TEXT NOT NULL,
    challenge TEXT NOT NULL CHECK (challenge IN ('http-01', 'cloudflare')),
    email TEXT NOT NULL,
    certificate_path TEXT,
    private_key_path TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'renewal_failed', 'expired')),
    not_before INTEGER,
    not_after INTEGER,
    renewal_attempts INTEGER NOT NULL DEFAULT 0,
    next_renewal_attempt INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX certificates_site_id ON certificates(site_id);
CREATE INDEX certificates_renewal ON certificates(state, not_after, next_renewal_attempt);

CREATE TABLE dns_integrations (
    provider TEXT PRIMARY KEY CHECK (provider = 'cloudflare'),
    zone_id TEXT NOT NULL,
    token_ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE dns_records (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'TXT')),
    hostname TEXT NOT NULL,
    content TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('manual', 'cloudflare')),
    provider_record_id TEXT,
    managed INTEGER NOT NULL DEFAULT 1 CHECK (managed IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX dns_records_site_id ON dns_records(site_id);
CREATE UNIQUE INDEX dns_records_provider_id ON dns_records(provider, provider_record_id) WHERE provider_record_id IS NOT NULL;

CREATE TABLE php_runtimes (
    version TEXT PRIMARY KEY CHECK (version IN ('8.3', '8.4', '8.5')),
    installed INTEGER NOT NULL DEFAULT 0 CHECK (installed IN (0, 1)),
    updated_at INTEGER NOT NULL
);

CREATE TABLE site_php_config (
    site_id TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    version TEXT NOT NULL REFERENCES php_runtimes(version),
    memory_mb INTEGER NOT NULL,
    upload_mb INTEGER NOT NULL,
    post_mb INTEGER NOT NULL,
    execution_seconds INTEGER NOT NULL,
    input_vars INTEGER NOT NULL,
    display_errors INTEGER NOT NULL DEFAULT 0 CHECK (display_errors IN (0, 1)),
    updated_at INTEGER NOT NULL
);
