# TomPanel MVP UI Decisions

**Status:** Approved for implementation planning  
**Date:** 2026-08-09  
**Source:** Interactive HTML prototypes in `docs/prototypes/`

## Product shell

TomPanel uses the approved **Operations-first** shell: a persistent left navigation on desktop, compact responsive navigation on smaller screens, a server identity in the header, and the current site's sections beneath its page header. The interface is modern-minimal, uses cobalt for primary actions, and keeps health, warnings, and destructive work explicit.

Production code must recreate the decisions with Go templates and shared CSS/JavaScript. Prototype HTML is a behavioral reference, not production code to copy wholesale.

## Approved surfaces

| Surface | Approved decision | Implementation contract | Prototype |
|---|---|---|---|
| Dashboard | Operations-first | Resource strip, sites table, recent jobs, and a prioritized attention column | [Prototype](../../prototypes/tompanel-dashboard-prototype.html) |
| Sites | Dense table | Search/filter sites and open a Site Overview before taking site-level actions | [Prototype](../../prototypes/tompanel-sites-list-prototype.html) |
| WordPress creation | Guided wizard | Configure WordPress, address, runtime, performance, DNS/SSL, then review and stream a durable job | [Prototype](../../prototypes/tompanel-create-site-prototype.html) |
| Laravel creation | Guided wizard | Collect repository and deploy settings, review the fixed pipeline, and require separate migration confirmation | [Prototype](../../prototypes/tompanel-laravel-site-prototype.html) |
| Site Overview | Operations summary | Show status, application, resources, managed services, recent activity, and attention items | [Prototype](../../prototypes/tompanel-site-overview-prototype.html) |
| Login and security | Focused gate | Username/password then TOTP; Security shows sessions and CLI-only administrator credential reset | [Prototype](../../prototypes/tompanel-login-security-prototype.html) |
| Domains and SSL | Hostname table | One row per primary/subdomain/parked/redirect hostname with DNS, SSL, and routing state | [Prototype](../../prototypes/tompanel-domains-ssl-prototype.html) |
| Files and access | Explorer plus access | Constrained file explorer beside SFTP accounts; Trash replaces immediate destructive deletion | [Prototype](../../prototypes/tompanel-files-access-prototype.html) |
| Runtime and PHP | Settings plus impact | Per-site PHP version/settings, FPM pool status, and explicit shared-extension impact review | [Prototype](../../prototypes/tompanel-runtime-php-prototype.html) |
| Databases | Resource table | Site-scoped databases/users with backup and credential rotation; phpMyAdmin is optional and private by default | [Prototype](../../prototypes/tompanel-databases-prototype.html) |
| WordPress management | Control center | Core/update policy, Nginx page cache, Redis Object Cache, system cron, and guarded update review | [Prototype](../../prototypes/tompanel-wordpress-management-prototype.html) |
| Backup and restore | Recovery-first | Backup status table and guarded restore flow with pre-restore backup and health check | [Prototype](../../prototypes/tompanel-backup-restore-prototype.html) |
| Site logs | Filterable stream | Read-only source/severity/search filters, pause/follow live, redaction status, and event details | [Prototype](../../prototypes/tompanel-site-logs-prototype.html) |
| Services | Managed-service table | Expose only TomPanel-owned units, show impacted sites, and require step-up before disruption | [Prototype](../../prototypes/tompanel-services-prototype.html) |
| Activity | Jobs and audit split view | Filter durable jobs separately from retained audit events; job detail shows ordered steps and redacted output | Derived from approved Dashboard job and table patterns |
| System | Sectioned server status | Show OS/security updates, reboot state, disk/swap, owned firewall rules, and explicit package/tool update reviews | Derived from approved Settings and Services patterns |
| Settings and integrations | Sectioned settings | Panel endpoint, Cloudflare/S3/SMTP, TOTP/session state, and CLI-only username/password reset | [Prototype](../../prototypes/tompanel-settings-integrations-prototype.html) |

## Shared interaction rules

1. Every mutation begins from an explicit action, shows scope and impact, then enters a durable job or guarded confirmation.
2. Destructive actions require typed confirmation where identity matters and password/TOTP step-up where the design spec requires it.
3. Failed activation keeps the last valid configuration or release active and presents retry/rollback in plain language.
4. Secrets are never re-rendered after initial creation and never appear in URLs, command arguments, job logs, or audit details.
5. Private endpoints and SSH tunnels are recommended defaults. Public exposure always shows hostname, port, TLS, firewall, and Cloudflare implications.
6. Shared resources are labeled before mutation: PHP extensions affect every site on that PHP version; system services show all impacted sites.
7. Inactive or unsupported controls are omitted. TomPanel does not imply FTP, shell access, LiteSpeed, arbitrary systemd, or arbitrary Laravel hooks.
8. Live status uses SSE with a clear connected/paused/reconnecting state. Important status never relies on color alone.
9. Tables collapse into labeled rows on narrow screens; dialogs remain keyboard operable; focus rings and semantic labels are required.
10. Empty, loading, failure, partial-success, and permission-denied states use the same layout rather than separate ornamental pages.

## Navigation contract

Main navigation: Dashboard, Sites, Domains, Databases, Backups, Services, Activity, System, Settings.

Site navigation: Overview, Domains & SSL, Files & Access, Runtime, Databases, Applications, Backups, Logs.

SFTP belongs under Files & Access. Cache belongs under the installed application when application-specific, while generic Laravel cache clear is shown in Applications. SSL belongs with Domains & SSL. This keeps the site navigation short without losing the approved capabilities.

## Explicit exclusions

- No password or username change form in the web Panel; use interactive `sudo tompanel admin ...` commands.
- No FTP/FTPS, browser terminal, arbitrary command runner, or arbitrary systemd unit input.
- No per-site LiteSpeed toggle. The MVP uses Nginx page cache and optional Redis.
- No fake per-site OPcache clear when sites share a PHP-FPM master.
- No general Cloudflare zone editor; only TomPanel-owned record operations are shown.
