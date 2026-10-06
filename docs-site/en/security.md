# Security

## Authentication

TomPanel uses a single-administrator model:

- **Password** — minimum 12 characters
- **TOTP** — required second factor (authenticator app)
- **Recovery codes** — shown once during setup, each usable one time

### Recovery

If you lose access, reset from the server console (not the browser):

```bash
sudo tompanel -config /etc/tompanel/config.toml admin reset-password
sudo tompanel -config /etc/tompanel/config.toml admin set-username
sudo tompanel -config /etc/tompanel/config.toml admin reset-totp
```

## Step-up authentication

Destructive actions (delete site, rotate credentials, disable SFTP, install WordPress) require **recent re-authentication** — you'll be asked to re-enter your password and TOTP code.

## Architecture

| Layer | Protection |
|---|---|
| Web panel | Unprivileged, loopback-only, no direct internet exposure |
| Privileged agent | Typed operations only — never accepts shell commands |
| Secrets | Field-encrypted at rest, never in job inputs or logs |
| Database | Site-scoped grants, no cross-site access |
| Firewall | UFW enabled with only necessary ports open |

## SSH tunnel access (recommended)

The panel is only accessible on `127.0.0.1:8080`. Connect from your computer:

```bash
ssh -L 8080:127.0.0.1:8080 root@your-server
```

Then open `http://127.0.0.1:8080` in your browser.

## Public HTTPS endpoint (optional)

See [Domains & SSL](domains.md) for setting up a public endpoint with a real certificate.

## Panel updates

Updates are Ed25519-signed and verified before installation. The updater:
- Snapshots database, config, and binaries
- Stages the update
- Health-checks after restart
- Rolls back the complete snapshot on failure

Updates fail closed until the operator installs the release key.
