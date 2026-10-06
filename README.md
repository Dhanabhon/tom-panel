# TomPanel

TomPanel is an open-source, web-based control panel for managing a single Linux VPS. It is designed for one administrator, multiple websites, and a simple operations-first workflow.

> [!WARNING]
> **Under active development — not ready for production hosting.**
> v0.1.0 is an early-access release: the MVP is feature-complete and passed a 10/10 acceptance drill on a real Ubuntu 24.04 VM, but it is intended for **evaluation on disposable servers only**. Do not host anything you cannot afford to lose. Expect breaking changes throughout the 0.x series, always keep off-server backups, and review [the changelog](CHANGELOG.md) before upgrading.

## Early access — what that means

| | Status |
| --- | --- |
| Install, first-run wizard, panel, all MVP features | ✅ Shipped and verified on a real VM |
| VM acceptance drill (10 checks on real Ubuntu 24.04) | ✅ Passed |
| Reproducible `.deb` + bootstrap one-command install | ✅ Released |
| Signed panel updates (Ed25519 key ceremony) | ⏳ Pending — updates fail closed until the operator installs a release key |
| Production data hosting | ⛔ Not yet — evaluate on disposable servers first |

During early access:

- **Breaking changes are expected** in every 0.x release — read the changelog before upgrading.
- **Always keep off-server backups** of anything important (Backups → S3/R2 encrypted upload).
- **Report anything unusual** — [the docs](https://dhanabhon.github.io/tom-panel/) and the built-in `tompanel doctor` cover most diagnosis.
- The **docs site** is live at [dhanabhon.github.io/tom-panel](https://dhanabhon.github.io/tom-panel/) (English and Thai).

## Quick start

On a fresh Ubuntu Server 24.04 LTS (AMD64) VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Dhanabhon/tom-panel/main/scripts/bootstrap.sh -o tompanel-bootstrap.sh
sh tompanel-bootstrap.sh
```

The bootstrap downloads the latest release, verifies its SHA-256, installs
TomPanel with hardened defaults (OpenSSH is allowed before UFW enables), and
prints the SSH tunnel command plus a one-time setup URL. The browser first-run
setup then creates your administrator account, TOTP secret, and recovery codes.

```bash
sh tompanel-bootstrap.sh 1.2.0     # pin a release version
sh tompanel-bootstrap.sh --check   # preflight only, changes nothing
sh tompanel-bootstrap.sh --offline ./tompanel_1.2.0_amd64.deb
```

## Goals

- Lightweight and reliable on a small VPS
- Simple single-admin operation without billing or customer roles
- Multiple isolated websites on one server
- Safe defaults with an auditable privileged boundary
- Guided installers for WordPress and Laravel
- Ubuntu LTS first, with room for Debian and a future Raspberry Pi Lite edition

## Current foundation

- Loopback-only web control panel for SSH tunnel or HTTPS reverse-proxy access
- First-run administrator setup, password login, TOTP, recovery codes, CSRF protection, and secure sessions
- Server-only commands for resetting the administrator username, password, or TOTP
- Encrypted SQLite-backed state and an audit log
- Durable background jobs with retry, cancellation, recovery, and live progress updates
- A peer-verified Unix socket between the unprivileged panel and its privileged helper
- Site lifecycle with managed Nginx, domains, DNS, SSL certificates, and per-site PHP-FPM pools
- A confined File Manager with trash, archives, and site-scoped SFTP accounts
- Site-scoped MariaDB databases with credential rotation and phpMyAdmin in private or public modes
- Guarded WordPress and Laravel installers with fixed deployment pipelines
- Health endpoint at `/healthz`

## Roadmap after 0.1.0

- First-run setup wizard: guided domain binding with live DNS verification
- Signed update pipeline activation (release key ceremony)
- Debian and Raspberry Pi OS targets
- Performance hardening for 512 MB–1 GB hosts beyond swap

## Supported platform

The first supported target is **Ubuntu Server 24.04 LTS on AMD64**. Debian and Raspberry Pi OS are future targets.

## Components

| Component | Purpose |
| --- | --- |
| `tompaneld` | Unprivileged web control panel and job manager |
| `tompanel-agent` | Root-owned helper with a small, closed operation set |
| `tompanel` | Local administration and recovery command |

The browser never talks directly to the privileged helper. `tompaneld` accepts local web requests and sends typed operations through a protected Unix socket.

## Development

TomPanel currently requires Go 1.26 or later.

```bash
go test ./...
go build ./cmd/...
```

Run the Ubuntu 24.04 AMD64 verification before testing on a VPS:

```bash
./scripts/test-docker.sh
```

This checks the Go test suite and race detector, static analysis, Linux builds, JavaScript syntax, and TomPanel-generated Nginx/PHP-FPM 8.3 configuration against Ubuntu's packages. PHP 8.3 is the default because Ubuntu 24.04 ships it; later PHP versions require an explicit package-source decision. It does not replace VPS acceptance for systemd, root-agent socket permissions, Linux users and filesystems, UFW and public networking, DNS/ACME, reboot recovery, or rollback under real service failures.

Example development configuration:

```toml
listen = "127.0.0.1:8080"
state_dir = "/var/lib/tompanel"
agent_socket = "/run/tompanel/agent.sock"
```

The panel deliberately rejects non-loopback listen addresses. Use an SSH tunnel during development:

```bash
ssh -L 8080:127.0.0.1:8080 user@server
```

Then open `http://127.0.0.1:8080` locally.

## Server diagnostics

Run a read-only health report (configuration, master key, database, agent
socket, nginx, firewall, systemd, disk) — it never changes anything:

```bash
tompanel -config /etc/tompanel/config.toml doctor
tompanel version
```

`doctor` exits non-zero when any check fails, so it is safe to use from
monitoring scripts. Paste its output when asking for support.

## Administrator recovery

Administrator credentials cannot be changed from an unauthenticated browser flow. Run recovery commands directly on the server:

```bash
tompanel -config /etc/tompanel/config.toml admin reset-password
tompanel -config /etc/tompanel/config.toml admin set-username
tompanel -config /etc/tompanel/config.toml admin reset-totp
```

For first-time setup, generate a single-use URL from an interactive server terminal:

```bash
tompanel -config /etc/tompanel/config.toml setup-url
```

## Security notes

- Do not expose the loopback HTTP listener directly to the internet.
- Use an SSH tunnel or the guided public HTTPS endpoint (Settings → Panel endpoint).
- Keep `/etc/tompanel/master.key` readable only by the TomPanel service account.
- Panel updates are signed (Ed25519) and fail closed until the operator installs the release key — see `docs/release-signing.md`.

## Operations and release

- Durable backups with manifests, guarded restore, retention, and optional age-encrypted S3/R2 uploads (see Settings)
- Site deletion with final backup, DNS release, and a seven-day quarantine
- Allowlisted service controls, bounded log reads with secret redaction, activity history, and read-only system metrics
- Optional Cloudflare, object storage, and SMTP integrations with encrypted secrets and connection tests
- Signed (Ed25519) transactional panel updates with snapshot rollback; see `docs/release-signing.md`
- Debian packaging, guided installer, and CI in `packaging/`, `scripts/`, and `.github/workflows/`

## Verification

```bash
go test ./...                                       # unit and integration tests
go vet ./...
./scripts/test-docker.sh                            # Ubuntu 24.04 verification container
./scripts/build-deb.sh 0.1.0                        # reproducible Debian package into dist/
npm --prefix tests/browser ci && npm --prefix tests/browser test   # browser smoke
```

Two builds of the same commit produce a byte-identical `.deb`; the release
workflow re-verifies this before attaching artifacts.

## Project status

**v0.1.0 early access is released.** The full VM acceptance drill passed
10/10 on a fresh Ubuntu 24.04 host (`scripts/acceptance-ubuntu-2404.sh`),
and the release `.deb` is attached to
[the GitHub release](https://github.com/Dhanabhon/tom-panel/releases/tag/v0.1.0).
Review and test before using it on a server that contains important data.

## License

[MIT](LICENSE)

Release history is documented in [CHANGELOG.md](CHANGELOG.md).
