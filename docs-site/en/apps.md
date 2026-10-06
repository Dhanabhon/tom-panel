# Applications

## WordPress

### Install

1. Navigate to your site → **Applications** → **Install WordPress**
2. Enter the admin username, email, and site title
3. TomPanel generates a secure password, creates a dedicated database, and installs WordPress
4. Copy the credentials shown — they are displayed exactly once

### Security

- All secrets travel through protected stdin — never in command-line arguments
- `DISALLOW_FILE_EDIT` and `FORCE_SSL_ADMIN` are enabled by default
- The WP-CLI binary is checksum-verified before use

### Updates

Go to **Applications** → **Manage WordPress**:

| Policy | Description |
|---|---|
| Security & minor | Automatic (default) |
| Major core | Manual |
| Plugins | Manual (independent toggle) |
| Themes | Manual (independent toggle) |

Updates create a database backup first. If the update fails, TomPanel rolls back automatically.

### Object cache

Enable the Redis object cache for better performance. Each site gets a dedicated ACL user with a unique key prefix — no shared access, no `FLUSHALL`.

## Laravel

### Install

1. Navigate to your site → **Applications** → **Deploy Laravel**
2. Enter your Git repository URL (HTTPS or SSH only — `file://` is rejected)
3. Choose the branch and whether to run Node.js builds
4. Confirm the deployment

### The pipeline

```
checkout → composer install → [npm ci && npm run build] →
[php artisan migrate --force (separately confirmed)] →
php artisan optimize → health check → atomic release activation
```

If any step fails, the current release stays live — zero-downtime deployment.

### Deploy keys for private repositories

TomPanel generates an Ed25519 key pair on the server. Add the public key to your Git host with read access.

### Queue workers

Enable managed systemd units for `queue:work` and the scheduler. TomPanel owns the units and cleans them up on disable.
