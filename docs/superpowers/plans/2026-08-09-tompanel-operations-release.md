# TomPanel Operations and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete backup/restore, services/logs, settings/integrations, package updates, installer/packaging, and Ubuntu 24.04 MVP release verification.

**Architecture:** Operational work uses the same durable jobs and closed agent operations as site provisioning. Provider credentials stay encrypted in SQLite; package/installer state is recorded as owned resources; VM acceptance tests prove real service integration and recovery behavior.

**Tech Stack:** Plans 1-3 APIs, `filippo.io/age`, AWS SDK for Go v2, Cloudflare REST API, SMTP, systemd, UFW, `unattended-upgrades`, Debian packaging, GitHub Actions Ubuntu 24.04 VMs.

## Global Constraints

- Local backup is labeled insufficient for VPS-loss recovery; optional S3/R2 objects are age-encrypted before upload.
- Stop new backups at 85% disk use or below 2 GB free space.
- Service actions expose only TomPanel-owned allowlisted units and require step-up for disruption.
- Official security updates may run unattended; reboots, general upgrades, PPA packages, phpMyAdmin/WP-CLI, and TomPanel updates require explicit confirmation.
- Installer stops on stack conflicts, allows OpenSSH before UFW, and never turns an existing host into a managed host by inference.
- A failed TomPanel update restores database snapshot, configuration, and binaries together.

---

## Test fixture contract

`newServiceManager` creates a manager with only the shipped allowlist and fake systemd transport. `testManifest`, `corruptSignature`, and `testPublicKey` return a deterministic signed-manifest fixture with one deliberately corrupted signature. `readFile` resolves a repository-relative fixture and fails the test on read error.

### Task 1: Backup manifests, local/S3 storage, retention, and restore

**Files:**
- Create: `migrations/0006_backups_integrations.sql`
- Create: `internal/backups/model.go`
- Create: `internal/backups/manifest.go`
- Create: `internal/backups/service.go`
- Create: `internal/backups/s3.go`
- Create: `internal/backups/service_test.go`
- Create: `internal/backups/manifest_test.go`
- Create: `internal/agent/backup_ops.go`
- Create: `internal/agent/backup_ops_test.go`
- Create: `internal/sites/delete.go`
- Create: `internal/sites/delete_test.go`
- Create: `internal/web/backup_handlers.go`
- Create: `internal/web/backup_handlers_test.go`
- Create: `web/templates/backups.html`

**Interfaces:**
- Produces: `backups.Manifest{Version, SiteID, CreatedAt, Files, Database, Checksums, ToolVersions, Consistency}`
- Produces: `backups.Service.Create`, `Restore`, `Delete`, `ApplyRetention`, `ScheduleDue`, `Verify`
- Adds: `sites.State` constants `deleting`, `quarantined`
- Produces: `sites.BuildDeleteJob(siteID string, removeManagedDNS bool) jobs.Definition`
- Adds operations: `backup.archive`, `backup.database_dump`, `backup.restore_temporary`, `backup.activate_restore`, `backup.disk_guard`

- [ ] **Step 1: Write manifest, disk-guard, and rollback tests**

```go
func TestDiskGuardStopsBackupBelowTwoGiB(t *testing.T) {
    err := CheckDisk(DiskState{Total: 80 << 30, Used: 79 << 30, Free: 1 << 30})
    if !errors.Is(err, ErrInsufficientDisk) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/backups ./internal/sites ./internal/agent -run 'TestDiskGuardStopsBackupBelowTwoGiB|TestEncryptedUploadContainsNoPlaintext|TestRestoreFailureReactivatesPreRestoreState|TestDeleteRequiresNameAndTOTP|TestQuarantineNeverDeletesExternalDNS' -v`  
Expected: FAIL because backup packages are absent.

- [ ] **Step 3: Implement streaming backup and guarded restore**

Create versioned JSON manifests, checksums, transactionally consistent MariaDB dumps, best-effort scheduled file archives, and optional maintenance mode for manual backups. `ScheduleDue` assigns stable randomized daily times per site and enqueues at most one automatic backup per day. Stream S3/R2 uploads through age encryption without plaintext staging. Restore verifies/decrypts, creates a pre-restore backup, restores temporary files/database, validates permissions and application health, atomically activates, and rolls back on failure. Keep seven automatic local backups per site; never silently delete manual backups. Site deletion requires exact-name plus TOTP step-up, completes a final backup, disables owned routes/workers, optionally removes owned Cloudflare records, moves metadata/data into seven-day quarantine, and purges only ledger-owned resources after expiry.

- [ ] **Step 4: Verify recovery drills with fake S3 and injected failures**

Run: `go test -race ./internal/backups ./internal/sites ./internal/agent ./internal/web`  
Expected: PASS for checksum mismatch, wrong age identity, S3 timeout/retry, disk guard, retention, pre-restore failure, health failure, quarantine restore/purge ownership, and local-only warning copy.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum migrations/0006_backups_integrations.sql internal/backups internal/sites internal/agent internal/web web/templates/backups.html
git commit -m "feat: add encrypted recovery and site quarantine"
```

### Task 2: Metrics, managed services, logs, Activity, and retention

**Files:**
- Create: `internal/operations/metrics.go`
- Create: `internal/operations/services.go`
- Create: `internal/operations/logs.go`
- Create: `internal/operations/retention.go`
- Create: `internal/operations/operations_test.go`
- Create: `internal/agent/service_ops.go`
- Create: `internal/agent/log_ops.go`
- Create: `internal/agent/service_ops_test.go`
- Create: `internal/web/operations_handlers.go`
- Create: `internal/web/operations_handlers_test.go`
- Create: `web/templates/services.html`
- Create: `web/templates/activity.html`
- Create: `web/templates/system.html`
- Create: `web/templates/site_logs.html`

**Interfaces:**
- Produces: `operations.Snapshot`, `ManagedService`, `LogQuery`, and `LogEvent`
- Adds operations: `service.inspect`, `service.restart`, `service.start`, `service.stop`, `log.read`
- Consumes: `jobs.Manager` events and `audit_events`

- [ ] **Step 1: Write allowlist, redaction, and retention tests**

```go
func TestServiceActionRejectsUnmanagedUnit(t *testing.T) {
    svc := newServiceManager(t)
    err := svc.Restart(context.Background(), "ssh.service")
    if !errors.Is(err, ErrUnmanagedService) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/operations ./internal/agent -run 'TestServiceActionRejectsUnmanagedUnit|TestLogReaderRedactsRegisteredSecrets|TestRetentionDoesNotRecursivelyFlood' -v`  
Expected: FAIL because operational packages are absent.

- [ ] **Step 3: Implement read paths and guarded actions**

Read current CPU, memory, load, swap, disk, and uptime from Linux without storing time series. Map stable product service keys to fixed systemd units; compute impacted sites from persisted runtime/resource data; require step-up before lifecycle actions. Read only owned log paths or journal units with line/byte/time bounds. Retain Nginx logs 14 days, jobs 30 days, audit events 180 days, and expire site Trash/quarantine only after their recorded deadlines. Pause cleanup before disk exhaustion without logging a failure loop.

- [ ] **Step 4: Verify approved operational UI**

Run: `go test -race ./internal/operations ./internal/agent ./internal/web`  
Expected: PASS. Services shows impacts before restart; Site Logs filters source/severity/search and exposes SSE state; Activity separates jobs from audit events; System shows update/reboot/firewall state without arbitrary controls.

- [ ] **Step 5: Commit**

```bash
git add internal/operations internal/agent internal/web web/templates
git commit -m "feat: add bounded server operations and logs"
```

### Task 3: Panel endpoint, Cloudflare, S3/R2, SMTP, and security settings

**Files:**
- Create: `internal/integrations/model.go`
- Create: `internal/integrations/cloudflare.go`
- Create: `internal/integrations/s3.go`
- Create: `internal/integrations/smtp.go`
- Create: `internal/integrations/integrations_test.go`
- Create: `internal/operations/endpoint.go`
- Create: `internal/operations/endpoint_test.go`
- Create: `internal/web/settings_handlers.go`
- Create: `internal/web/settings_handlers_test.go`
- Create: `web/templates/settings.html`
- Modify: `internal/web/app.go`

**Interfaces:**
- Produces: `integrations.Service.SaveCloudflare`, `SaveS3`, `SaveSMTP`, `Test`, `SendAlert(ctx context.Context, alert integrations.Alert) error`
- Produces: `operations.EndpointConfig{Mode, Hostname string, Port uint16, CloudflareProxy bool}` and `BuildEndpointChangeJob`
- Consumes: field encryption from `store.Store`, DNS/ACME from `domains.Service`, and UFW/Nginx agent operations.

- [ ] **Step 1: Write endpoint and secret-storage tests**

```go
func TestCloudflareProxyRejectsUnsupportedPort(t *testing.T) {
    err := ValidateEndpoint(EndpointConfig{Mode: "public", Hostname: "panel.example.com", Port: 9443, CloudflareProxy: true})
    if !errors.Is(err, ErrCloudflarePort) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/integrations ./internal/operations ./internal/web -run 'TestCloudflareProxyRejectsUnsupportedPort|TestEndpointRejectsSiteHostname|TestSettingsNeverRenderStoredSecret' -v`  
Expected: FAIL because integrations/settings are absent.

- [ ] **Step 3: Implement encrypted integrations and zero-downtime endpoint changes**

Store provider secrets encrypted with field-specific AAD and render only configured/not-configured states. Test Cloudflare scopes, S3 write/read/delete of a random probe, and SMTP handshake without persisting probe content. `SendAlert` sends bounded templates for failed jobs, security notices, and recovery outcomes; provider errors keep request IDs but redact recipients and secrets. Endpoint change validates reserved hostname, port collision, Cloudflare 443/8443 rule, DNS, certificate, Nginx, and UFW; health-check the new address before removing the old route. Render no web username/password change controls and show only CLI recovery commands.

- [ ] **Step 4: Verify settings behavior and rollback**

Run: `go test -race ./internal/integrations ./internal/operations ./internal/web`  
Expected: PASS for wrong provider scope, encrypted roundtrip, redacted errors, endpoint collision, certificate failure, firewall failure, health failure, and old-endpoint preservation.

- [ ] **Step 5: Commit**

```bash
git add internal/integrations internal/operations/endpoint* internal/web web/templates/settings.html
git commit -m "feat: add guarded endpoint and optional integrations"
```

### Task 4: OS packages and transactional TomPanel updates

**Files:**
- Create: `internal/operations/packages.go`
- Create: `internal/operations/update.go`
- Create: `internal/operations/packages_test.go`
- Create: `internal/operations/update_test.go`
- Create: `internal/agent/package_ops.go`
- Create: `internal/agent/update_ops.go`
- Create: `internal/agent/package_ops_test.go`
- Create: `internal/web/update_handlers.go`
- Create: `internal/web/update_handlers_test.go`

**Interfaces:**
- Produces: `operations.PackageStatus`, `ToolUpdate`, `ReleaseManifest`, `BuildPackageJob`, `BuildToolUpdateJob`, `BuildTomPanelUpdateJob`
- Adds operations: `package.apply_official`, `package.apply_ppa`, `tool.update_verified`, `tompanel.stage_update`, `tompanel.activate_update`, `tompanel.rollback_update`

- [ ] **Step 1: Write signature and rollback tests**

```go
func TestUpdateRejectsManifestWithBadSignature(t *testing.T) {
    _, err := VerifyReleaseManifest(testManifest(), corruptSignature(), testPublicKey())
    if !errors.Is(err, ErrReleaseSignature) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/operations ./internal/agent -run 'TestUpdateRejectsManifestWithBadSignature|TestFailedMigrationRestoresDatabaseAndBinaries|TestPPAUpdateRequiresConfirmation|TestToolUpdateRequiresConfirmation' -v`  
Expected: FAIL because update operations are absent.

- [ ] **Step 3: Implement explicit package boundaries and full-state rollback**

Read unattended-upgrades/reboot state without mutation and state that distribution upgrades are unsupported. Official security updates may follow OS policy; general and PPA upgrades require confirmed allowlisted package sets. phpMyAdmin and WP-CLI updates use explicit `ToolUpdate` jobs with upstream signature/checksum verification before atomic replacement. Verify TomPanel's signed stable manifest, SHA-256, and Ed25519 signature; pause mutable jobs; snapshot SQLite/config/binaries; stage package and migrations; restart and health-check; restore the complete snapshot set on failure.

- [ ] **Step 4: Verify update crash cases**

Run: `go test -race ./internal/operations ./internal/agent ./internal/web`  
Expected: PASS for download truncation, signature mismatch, package failure, migration failure, restart failure, health failure, rollback, and read-only Dashboard availability while jobs are paused.

- [ ] **Step 5: Commit**

```bash
git add internal/operations internal/agent internal/web
git commit -m "feat: add explicit package and panel updates"
```

### Task 5: Debian package, installer, CI, and MVP acceptance drills

**Files:**
- Create: `packaging/debian/control`
- Create: `packaging/debian/postinst`
- Create: `packaging/debian/prerm`
- Create: `packaging/systemd/tompanel.service`
- Create: `packaging/systemd/tompanel-agent.service`
- Create: `packaging/tmpfiles/tompanel.conf`
- Create: `packaging/logrotate/tompanel`
- Create: `scripts/install.sh`
- Create: `scripts/uninstall.sh`
- Create: `scripts/acceptance-ubuntu-2404.sh`
- Create: `docs/release-signing.md`
- Create: `tests/integration/release_test.go`
- Create: `tests/browser/package.json`
- Create: `tests/browser/smoke.spec.mjs`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/ubuntu-integration.yml`
- Create: `README.md`
- Create: `SECURITY.md`

**Interfaces:**
- Consumes all shipped binaries and migration/assets embedding.
- Produces a signed AMD64 `.deb`, checksum/signature files, installer conflict report, and repeatable acceptance transcript.

- [ ] **Step 1: Write package and installer assertions**

```go
func TestUnitsKeepWebDaemonUnprivileged(t *testing.T) {
    unit := readFile(t, "../../packaging/systemd/tompanel.service")
    for _, want := range []string{"User=tompanel", "NoNewPrivileges=true", "PrivateTmp=true"} {
        if !strings.Contains(unit, want) { t.Fatalf("missing %s", want) }
    }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./tests/integration -run 'TestUnitsKeepWebDaemonUnprivileged|TestAgentUnitIsHardened' -v`  
Expected: FAIL because packaging files are absent.

- [ ] **Step 3: Implement package lifecycle and safe installer**

Build reproducible binaries with embedded templates/migrations. Package hardened units, socket/runtime directories, log rotation, and exact filesystem ownership. Installer checks Ubuntu 24.04/AMD64/resources/public IPv4/conflicting stack, creates 2 GB swap only when none exists, asks explicit PHP-PPA consent, installs OpenSSH allowance before enabling UFW, starts private mode, and prints the 15-minute setup URL plus SSH tunnel command. Uninstall removes only ledger-owned resources and preserves site/backups unless the administrator confirms their exact paths. Document offline Ed25519 release signing, key custody, rotation, checksum generation, and public-key distribution in `docs/release-signing.md`.

Implement `tests/browser/smoke.spec.mjs` against a private-endpoint fixture. Cover login with TOTP, keyboard navigation, the Static/PHP/Reverse Proxy/WordPress/Laravel creation flows, job progress, and exact-name plus step-up confirmation for destructive actions.

- [ ] **Step 4: Run every release gate on a fresh VM**

Run: `sudo ./scripts/acceptance-ubuntu-2404.sh`  
Expected: PASS for clean install/uninstall; private bootstrap/public endpoint; five site types; bad-config protection; per-site boundaries; local and encrypted S3 restore; HTTP-01/DNS-01 renewal; job resume; TomPanel update rollback; log secret scan; unauthorized-agent rejection.

- [ ] **Step 5: Run CI and commit the release slice**

Run: `go test ./... && go vet ./... && shellcheck scripts/*.sh packaging/debian/postinst packaging/debian/prerm && npm --prefix tests/browser ci && npm --prefix tests/browser test`  
Expected: PASS.

```bash
git add packaging scripts tests/integration tests/browser .github README.md SECURITY.md docs/release-signing.md
git commit -m "build: package and verify tompanel mvp"
```
