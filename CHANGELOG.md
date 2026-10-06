# Changelog

All notable changes to TomPanel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[SemVer](https://semver.org/) — during the 0.x series, minor versions may
contain breaking changes.

## [0.1.0] - 2026-10-06 — Early access

The first early-access release: a complete single-admin hosting panel for one
Ubuntu Server 24.04 LTS (AMD64) machine, reached through an SSH tunnel or a
guided HTTPS endpoint. Everything below ships in this release.

### Added

- **Control plane** — loopback-only web panel with single-admin setup,
  password + TOTP + recovery-code sign-in, CSRF protection, step-up
  re-authentication for sensitive actions, encrypted SQLite state, durable
  resumable background jobs with redacted output, and a hardened root agent
  that accepts only typed operations over a peer-verified Unix socket
- **Sites** — static, PHP, and reverse-proxy sites with durable provisioning,
  disable/re-enable with rollback, managed Nginx configurations, domains with
  DNS records, HTTP-01/DNS-01 certificates, and per-site PHP-FPM pools
- **Files & access** — a confined File Manager (upload, edit, archives with
  bomb guards, trash with restore) and site-scoped SFTP accounts chrooted with
  shell, forwarding, tunneling, and agent access disabled
- **Databases** — site-scoped MariaDB databases, two-phase credential rotation
  that keeps the old password until the new one passes a health check, dump /
  restore, and phpMyAdmin in private, public-subdomain, or public-port modes
- **Applications** — a guarded WordPress installer with generated secrets,
  independent update channels, system cron, and a site-scoped Redis object
  cache; a fixed Laravel deployment pipeline with confirmed migrations,
  health-gated atomic release activation, and managed queue workers
- **Operations** — manual and scheduled backups with manifests and optional
  age-encrypted S3/R2 uploads, guarded restores with automatic rollback,
  seven-day site-deletion quarantine, allowlisted service controls with site
  impact reports, bounded and secret-redacted log reads, activity history,
  and read-only system metrics
- **Integrations & updates** — Cloudflare, S3/R2, and SMTP connections with
  encrypted secrets and connection tests; Ed25519-signed transactional panel
  updates that snapshot database, configuration, and binaries and roll the
  complete set back on failure
- **Packaging & CLI** — a reproducible Debian package, a guided installer that
  allows OpenSSH before enabling UFW, a one-command bootstrap that verifies
  release checksums, and a `tompanel` CLI with `setup-url`, `migrate`,
  `doctor` (read-only health report), `version`, and offline administrator
  recovery

### Security

- The web panel runs unprivileged and binds loopback only; the privileged
  agent never accepts a shell command string
- Secrets are field-encrypted with a master key stored outside the database
  and never appear in job inputs, audit events, or logs
- Destructive actions require exact-name confirmation plus recent
  re-authentication
- Panel updates fail closed until the operator installs the published release
  key

### Known limitations (early access)

- Ubuntu Server 24.04 LTS on AMD64 only; one administrator per server
- The full VM acceptance drill and the offline release-key ceremony are still
  pending — treat this release as suitable for evaluation, not production
  hosting
- Containers, mail hosting, multi-server operation, and LiteSpeed are excluded
  by design

[0.1.0]: https://github.com/Dhanabhon/tom-panel/releases/tag/v0.1.0
