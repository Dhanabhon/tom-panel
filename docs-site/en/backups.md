# Backups

## Manual backup

Navigate to your site → **Backups** → **Back up now**.

TomPanel:
- Archives all site files
- Dumps all site databases with consistent snapshots
- Records a versioned manifest with checksums
- Verifies the archive integrity

## Scheduled backups

Backups run automatically at a stable time per site (deterministic from the site ID). The seven newest scheduled backups are retained; manual backups are never auto-deleted.

## Disk guard

New backups stop when disk usage exceeds 85% or free space drops below 2 GB. A warning appears on the Backups page.

## Restore

1. Find the backup in the list
2. Confirm the restore
3. TomPanel:
   - Creates a pre-restore backup (safety net)
   - Stages the restore in a temporary area
   - Validates permissions and structure
   - Activates atomically (or rolls back on failure)

## S3/R2 encrypted upload

1. Go to **Settings** → **Object storage (S3/R2)**
2. Enter your endpoint, bucket, credentials, and an age recipient public key
3. Click **Test connection**

Backups are encrypted client-side with `age` before upload. The server never has access to unencrypted data in transit.

## Site deletion

Deleting a site:

1. Takes a final backup
2. Disables all Nginx routes and workers
3. Optionally releases TomPanel-owned DNS records
4. Drops site databases
5. Moves all data to **quarantine** (7-day recovery window)

To delete: go to **Backups** → **Danger zone**, type the exact domain name, and confirm. Requires recent re-authentication.

After 7 days, quarantined data is purged permanently.
