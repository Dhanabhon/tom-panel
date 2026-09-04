# TomPanel

TomPanel is an open-source, web-based control panel for managing a single Linux VPS. It is designed for one administrator, multiple websites, and a simple operations-first workflow.

> TomPanel is under active development. The current codebase provides the control-plane foundation and is not ready for production hosting yet.

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
- Health endpoint at `/healthz`

## MVP roadmap

- Multiple sites with overview and management flows
- Primary domains, subdomains, parked domains, redirects, DNS, and SSL
- Per-site PHP versions, extensions, and runtime configuration
- Database management with optional phpMyAdmin exposure through a subdomain, private access, or a selected port
- WordPress and Laravel installers
- WordPress-specific cache, object cache, LiteSpeed, and update controls
- File management, backups and restore, FTP access, and cache clearing
- Optional Cloudflare integration

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
- Use an SSH tunnel or a correctly configured HTTPS reverse proxy.
- Keep `/etc/tompanel/master.key` readable only by the TomPanel service account.
- Run the privileged helper only through the supported service configuration once installer packaging is available.

## Project status

Installation scripts, systemd units, complete HTTPS provisioning, and production acceptance testing are still pending. Review and test the code before using it on a server that contains important data.

## License

[MIT](LICENSE)
