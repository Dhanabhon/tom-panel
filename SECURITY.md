# Security policy

TomPanel is designed for one administrator on a single Linux VPS.

## Reporting

Report security issues privately to `security@tompanel.example`. Please
include reproduction steps and affected versions; do not open public issues
for vulnerabilities.

## Model

- The web panel runs unprivileged and listens on loopback only; reach it
  through an SSH tunnel or the guided HTTPS endpoint.
- A root helper exposes a fixed set of typed operations over a peer-verified
  Unix socket. It never accepts shell strings.
- Secrets are field-encrypted with a master key stored outside the database
  and never appear in job inputs, audit events, or logs.
- Destructive actions require exact-name confirmation plus recent
  re-authentication (step-up).

## Server hardening expectations

- Keep `TOMPANEL_RELEASE_KEY` pinned to the published signing key before
  enabling panel updates.
- Keep `/etc/tompanel/master.key` readable only by the service account.
- Do not expose port 8080 through the firewall.
