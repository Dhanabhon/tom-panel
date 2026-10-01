CREATE TABLE app_installations_v2 (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    site_id TEXT NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    app TEXT NOT NULL CHECK (app IN ('wordpress', 'laravel')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'installing', 'active', 'failed')),
    version TEXT,
    database_suffix TEXT,
    admin_username TEXT NOT NULL DEFAULT '',
    admin_email TEXT NOT NULL DEFAULT '',
    admin_secret BLOB,
    db_secret BLOB,
    repository TEXT,
    branch TEXT,
    node_build INTEGER NOT NULL DEFAULT 0 CHECK (node_build IN (0, 1)),
    deploy_public_key TEXT,
    current_release TEXT,
    policy_minor INTEGER NOT NULL DEFAULT 1 CHECK (policy_minor IN (0, 1)),
    policy_major INTEGER NOT NULL DEFAULT 0 CHECK (policy_major IN (0, 1)),
    policy_plugins INTEGER NOT NULL DEFAULT 0 CHECK (policy_plugins IN (0, 1)),
    policy_themes INTEGER NOT NULL DEFAULT 0 CHECK (policy_themes IN (0, 1)),
    system_cron INTEGER NOT NULL DEFAULT 0 CHECK (system_cron IN (0, 1)),
    page_cache INTEGER NOT NULL DEFAULT 0 CHECK (page_cache IN (0, 1)),
    redis_cache INTEGER NOT NULL DEFAULT 0 CHECK (redis_cache IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT INTO app_installations_v2(id, site_id, app, state, version, database_suffix, admin_username, admin_email, admin_secret, db_secret,
    repository, branch, node_build, deploy_public_key, current_release,
    policy_minor, policy_major, policy_plugins, policy_themes, system_cron, page_cache, redis_cache, created_at, updated_at)
SELECT id, site_id, app, state, version, database_suffix, admin_username, admin_email, admin_secret, db_secret,
    NULL, NULL, 0, NULL, NULL,
    policy_minor, policy_major, policy_plugins, policy_themes, system_cron, page_cache, redis_cache, created_at, updated_at
FROM app_installations;

DROP TABLE app_installations;
ALTER TABLE app_installations_v2 RENAME TO app_installations;
