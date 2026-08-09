# TomPanel MVP Implementation Plan Index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver TomPanel MVP as four independently reviewable implementation slices on Ubuntu Server 24.04 LTS.

**Architecture:** A Go modular monolith (`tompaneld`) owns validation, HTML, SQLite, jobs, and audit state. A separate root process (`tompanel-agent`) accepts only versioned typed operations over a peer-verified Unix socket; the CLI handles diagnostics and offline administrator recovery.

**Tech Stack:** Go 1.26.x, `net/http`, `html/template`, vanilla CSS/JavaScript, SSE, `modernc.org/sqlite`, Nginx, PHP-FPM 8.3-8.5, MariaDB 10.11, optional Redis, systemd, OpenSSH SFTP, lego ACME, age, AWS SDK v2.

## Global Constraints

- Target only fresh Ubuntu Server 24.04 LTS on AMD64 for the MVP.
- Keep `tompaneld` unprivileged; only `tompanel-agent` runs as root.
- Agent operations are typed, peer-UID checked, bounded, and never accept a shell command string.
- SQLite uses WAL, foreign keys, busy timeout, durable synchronous writes, and transactional forward migrations.
- Every mutation is a durable job with redacted output, idempotent steps, ownership records, and safe retry boundaries.
- Validate generated configuration before atomic activation; retain and restore the last valid state on failure.
- One administrator only; username/password/TOTP reset is CLI-only after bootstrap.
- No containers, FTP/FTPS, browser shell, LiteSpeed, arbitrary systemd, arbitrary Laravel hooks, Debian, or ARM64 scaffolding.
- Rebuild approved UI behavior from `docs/superpowers/specs/2026-08-09-tompanel-ui-decisions.md`; do not promote prototype code directly.

---

## Execution order

| Order | Plan | Independently testable outcome | Depends on |
|---|---|---|---|
| 1 | `2026-08-09-tompanel-foundation-control-plane.md` | Private login, SQLite state, root-agent handshake, durable demo job, Dashboard shell | None |
| 2 | `2026-08-09-tompanel-sites-domains-runtime.md` | Static/PHP/reverse-proxy site creation, domains/SSL, PHP pools, disable/re-enable | Plan 1 |
| 3 | `2026-08-09-tompanel-applications-data-access.md` | Files/SFTP, MariaDB/phpMyAdmin, WordPress, Laravel, site cache operations | Plans 1-2 |
| 4 | `2026-08-09-tompanel-operations-release.md` | Backup/restore, logs/services, integrations, updates, packaging, release gates | Plans 1-3 |

Do not execute plans in parallel across this boundary. Tasks inside a plan may be parallel only when their `Interfaces` blocks do not consume each other.

## Specification coverage

| Design specification sections | Owning plan |
|---|---|
| 4-9: environment, stack, architecture, filesystem, data, authentication | Foundation and Control Plane |
| 10-13 and PHP in 14: sites, jobs, provisioning, domains, DNS, SSL, runtime | Sites, Domains, and Runtime |
| MariaDB/cache in 14 and 15-17: files, SFTP, databases, phpMyAdmin, WordPress, Laravel | Applications, Data, and Access |
| 18-21: backups, services/logs, packages, deletion/recovery | Operations and Release |
| 22-23: approved UI and error behavior | Every plan, with UI decisions as the shared contract |
| 24-25: automated checks, release gates, risks | Operations and Release, with lower-level tests in every prior plan |
| 26: deferred roadmap | Deliberately excluded from all MVP plans |
| 27: deployment-time inputs | Settings UI plus installer prompts in Operations and Release |

## Locked repository structure

```text
cmd/tompanel/                 # CLI and offline recovery
cmd/tompaneld/                # unprivileged web daemon
cmd/tompanel-agent/           # privileged typed-operation agent
internal/agentapi/            # shared socket protocol and concrete client
internal/auth/                # bootstrap, login, sessions, TOTP, step-up
internal/config/              # TOML configuration loading and validation
internal/store/               # SQLite connection, migrations, repositories
internal/jobs/                # durable jobs, steps, SSE, redaction
internal/sites/               # site lifecycle and provisioning plans
internal/domains/             # domains, Nginx routing, DNS and ACME orchestration
internal/runtime/             # PHP-FPM and cache settings
internal/files/               # confined File Manager operations
internal/databases/           # MariaDB and phpMyAdmin lifecycle
internal/apps/                # WordPress and Laravel recipes
internal/backups/             # manifests, age, local and S3/R2 restore
internal/operations/          # services, logs, packages and server metrics
internal/integrations/        # Cloudflare, S3/R2 and SMTP settings
internal/web/                 # routes, middleware, handlers and view models
web/templates/                # shared layouts and page templates
web/static/                   # shared CSS and small JavaScript modules
migrations/                   # embedded ordered SQLite migrations
packaging/                    # Debian package, systemd, tmpfiles and logrotate
scripts/                      # installer and VM acceptance helpers
tests/integration/            # Ubuntu 24.04 integration tests
```

Packages may add focused files inside these directories, but must not add a generic repository layer, dependency-injection framework, plugin system, or frontend build chain.

## Plan-wide verification

- [ ] Run `go test ./...` and require exit code 0.
- [ ] Run `go vet ./...` and require exit code 0.
- [ ] Run `go test -race ./internal/...` and require exit code 0 on AMD64 CI.
- [ ] Run `govulncheck ./...` and record accepted findings with exact dependency versions.
- [ ] Run `shellcheck scripts/*.sh packaging/**/*.sh` for shipped shell files.
- [ ] Run `npm --prefix tests/browser ci && npm --prefix tests/browser test` for login, TOTP, site wizard, and destructive-confirmation browser smoke tests.
- [ ] Run the Ubuntu 24.04 VM acceptance suite described in Plan 4 before tagging an MVP release.
- [ ] Confirm `git grep -nE '(password|token|secret|credential)=' -- '*.log' tests/fixtures` returns no committed secret material.

## Completion definition

The MVP is complete only when all four plans pass their acceptance checks and every release gate in Section 24 of the approved design specification has an automated or documented VM drill with captured output.
