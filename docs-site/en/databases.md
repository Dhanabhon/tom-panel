# Databases

## Create a database

1. Navigate to your site → **Databases**
2. Enter a suffix (e.g., `shop` — the full name becomes `tp_yoursiteid_shop`)
3. Click **Create database**

TomPanel:
- Creates the MariaDB database and user
- Grants the user access to only this database
- Shows the password exactly once — copy it immediately

## Credential rotation

TomPanel uses a two-phase rotation that never breaks your running site:

1. Click **Rotate credential**
2. TomPanel creates a new user, updates your application's config, health-checks, then retires the old user
3. If anything fails, the old credential keeps working

## Backup & restore

| Action | How |
|---|---|
| Back up | Click **Back up** — creates a consistent dump |
| Restore | Find the backup in the list, confirm, click **Restore** |

Backups are stored on the server and can be optionally encrypted and uploaded to S3/R2.

## phpMyAdmin

### Modes

| Mode | Description |
|---|---|
| **Private** (recommended) | Loopback-only, accessible through SSH tunnel |
| **Public subdomain** | Dedicated HTTPS hostname |
| **Public port** | HTTPS on a custom port |

### Enable

1. Go to **Databases** → **phpMyAdmin**
2. Choose a mode
3. For public modes, enter a hostname and ACME email
4. Click **Enable phpMyAdmin**

Public modes add rate limiting and HTTP Basic Auth before the phpMyAdmin login.

> **Note:** The admin password for Basic Auth is shown once. Store it securely.
