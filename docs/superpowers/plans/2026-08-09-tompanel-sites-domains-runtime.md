# TomPanel Sites, Domains, and Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create, inspect, activate, disable, and re-enable Static, PHP, and Reverse Proxy sites with safe Nginx, DNS/SSL, Linux-user, and PHP-FPM boundaries.

**Architecture:** Product packages build immutable provisioning plans and durable job steps. Only closed root-agent operations touch Linux users, files, UFW, Nginx, PHP-FPM, or certificate paths; each created resource is recorded before later cleanup can reference it.

**Tech Stack:** Foundation plan APIs, Go `os.Root`, Nginx, PHP-FPM 8.3-8.5, systemd, UFW, `go-acme/lego`, Cloudflare DNS API.

## Global Constraints

- Consume the concrete foundation interfaces exactly as documented in Plan 1.
- Site types in this slice: Static, PHP, Reverse Proxy. WordPress and Laravel join in Plan 3.
- Reverse Proxy manages routing/TLS only; it never manages the upstream process.
- Every generated config is rendered to a temporary file, validated, atomically activated, health-checked, and rolled back on failure.
- Final backup, quarantine, and purge are implemented with the backup service in Plan 4; this slice exposes disable/re-enable but no premature delete control.

---

## Test fixture contract

`decodeEnsureDirectories` decodes and validates only the public request payload. `dnsServiceWithRecord` creates a temporary store plus fake Cloudflare transport containing the supplied record. `failingProvisionEnv` registers fake agent operations and fails the named step once; its `RunAndRetry` resumes the persisted job and `AgentCalls` returns the durable call count for an operation.

### Task 1: Site, domain, certificate, and runtime persistence

**Files:**
- Create: `migrations/0002_sites.sql`
- Create: `internal/sites/model.go`
- Create: `internal/sites/repository.go`
- Create: `internal/sites/validate.go`
- Create: `internal/sites/repository_test.go`
- Create: `internal/sites/validate_test.go`

**Interfaces:**
- Produces: `sites.Kind` constants `static`, `php`, `reverse_proxy`
- Produces: `sites.State` constants `provisioning`, `active`, `failed`, `disabled`
- Produces: `sites.CreateInput`, `sites.Site`, and `sites.Repository`
- Produces: `ValidateCreate(input CreateInput, occupied []Endpoint) error`

- [ ] **Step 1: Write validation and transaction tests**

```go
func TestValidateCreateRejectsEndpointCollision(t *testing.T) {
    in := CreateInput{Kind: KindPHP, PrimaryDomain: "shop.example.com", HTTPSPort: 443, PHPVersion: "8.4"}
    err := ValidateCreate(in, []Endpoint{{Hostname: "shop.example.com", Port: 443, Owner: "panel"}})
    if !errors.Is(err, ErrEndpointOccupied) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm the tests fail**

Run: `go test ./internal/sites -run 'TestValidateCreateRejectsEndpointCollision|TestStateTransitionRejectsActiveToProvisioning' -v`  
Expected: FAIL because the package is absent.

- [ ] **Step 3: Implement schema, opaque IDs, and bounded validation**

Create `sites`, `domains`, `certificates`, `php_runtimes`, and `site_php_config` tables with foreign keys and unique `(hostname, port)` ownership. Use 128-bit random lowercase hex IDs; validate IDNA hostnames, ports, PHP versions, reverse-proxy loopback targets, and explicit state transitions.

- [ ] **Step 4: Verify repositories under concurrency**

Run: `go test -race ./internal/sites -count=20`  
Expected: PASS; two transactions cannot claim the same hostname and port.

- [ ] **Step 5: Commit**

```bash
git add migrations/0002_sites.sql internal/sites
git commit -m "feat: add site lifecycle persistence"
```

### Task 2: Linux site identity, directories, and Nginx typed operations

**Files:**
- Create: `internal/agent/site_ops.go`
- Create: `internal/agent/site_ops_test.go`
- Create: `internal/domains/nginx.go`
- Create: `internal/domains/nginx_test.go`
- Create: `internal/domains/testdata/*.golden`
- Modify: `internal/agent/operations.go`

**Interfaces:**
- Adds operations: `site.ensure_identity`, `site.ensure_directories`, `nginx.validate_activate`, `nginx.disable`, `ufw.ensure_rule`, `ufw.remove_owned_rule`
- Produces: `domains.RenderNginx(site sites.Site, hostnames []Hostname) ([]byte, error)`
- Consumes/records: `managed_resources(kind, external_id, path, owner_job_id)`

- [ ] **Step 1: Write traversal, ownership, and golden rendering tests**

```go
func TestEnsureDirectoriesRejectsCallerPath(t *testing.T) {
    _, err := decodeEnsureDirectories(json.RawMessage(`{"site_id":"../../etc"}`))
    if err == nil { t.Fatal("path-shaped site id accepted") }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/agent ./internal/domains -run 'TestEnsureDirectoriesRejectsCallerPath|TestRenderPHPVirtualHost' -v`  
Expected: FAIL because operations and renderer are absent.

- [ ] **Step 3: Implement deterministic identities and activation**

Derive Linux names from validated opaque IDs inside the agent; callers never submit absolute paths, usernames, unit names, or config destinations. Create root-owned chroot roots and bounded writable subdirectories. `nginx.validate_activate` writes a temporary file, runs `/usr/sbin/nginx -t` via an argument array, backs up only the owned active file, renames atomically, reloads Nginx, health-checks localhost with the Host header, and restores on failure.

- [ ] **Step 4: Verify with fake executables and filesystem fixtures**

Run: `go test -race ./internal/agent ./internal/domains`  
Expected: PASS for validator failure, reload failure, health failure, rollback, wrong ownership, and unknown resource removal.

- [ ] **Step 5: Commit**

```bash
git add internal/agent internal/domains
git commit -m "feat: add confined site and nginx operations"
```

### Task 3: Domain, Cloudflare DNS ownership, and ACME workflows

**Files:**
- Modify: `go.mod`
- Create: `internal/domains/service.go`
- Create: `internal/domains/dns.go`
- Create: `internal/domains/acme.go`
- Create: `internal/domains/service_test.go`
- Create: `internal/domains/dns_test.go`
- Create: `internal/domains/acme_test.go`
- Create: `internal/web/domain_handlers.go`
- Create: `internal/web/domain_handlers_test.go`
- Create: `web/templates/domains.html`
- Create: `web/templates/site_domains.html`

**Interfaces:**
- Produces: `domains.Service.AddHostname`, `Park`, `Redirect`, `CheckDNS`, `IssueCertificate`, `RenewDue`
- Adds agent operation: `certificate.activate`
- Consumes encrypted Cloudflare token through `store.Decrypt`; persists provider record IDs and TomPanel ownership tags.

- [ ] **Step 1: Write ownership and certificate safety tests**

```go
func TestDeleteDNSRefusesExternalRecord(t *testing.T) {
    svc := dnsServiceWithRecord(t, Record{ProviderID: "cf-1", Managed: false})
    if err := svc.Delete(context.Background(), "cf-1"); !errors.Is(err, ErrExternalResource) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/domains ./internal/web -run 'TestDeleteDNSRefusesExternalRecord|TestRenewFailureKeepsValidCertificate' -v`  
Expected: FAIL because DNS/ACME services are absent.

- [ ] **Step 3: Implement manual DNS, Cloudflare, HTTP-01, and DNS-01**

Add lego. Manual mode returns exact A/AAAA/CNAME instructions and bounded propagation state. Cloudflare requests use only zone read and DNS edit, save record IDs immediately, and never list unrelated records as editable. Renewal uses jitter, bounded exponential backoff, provider `Retry-After`, and activates a certificate only after Nginx validation and health checks.

- [ ] **Step 4: Verify handlers and provider fakes**

Run: `go test -race ./internal/domains ./internal/web`  
Expected: PASS for redirects, wildcard DNS-01, propagation pending, provider timeout, renewal failure, and exact-hostname certificate sets.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/domains internal/web web/templates/domains.html web/templates/site_domains.html
git commit -m "feat: add managed domains dns and certificates"
```

### Task 4: PHP-FPM versions, pools, settings, and shared extensions

**Files:**
- Create: `internal/runtime/php.go`
- Create: `internal/runtime/php_test.go`
- Create: `internal/runtime/render.go`
- Create: `internal/runtime/testdata/*.golden`
- Create: `internal/agent/php_ops.go`
- Create: `internal/agent/php_ops_test.go`
- Create: `internal/web/runtime_handlers.go`
- Create: `internal/web/runtime_handlers_test.go`
- Create: `web/templates/site_runtime.html`
- Modify: `internal/agent/operations.go`

**Interfaces:**
- Produces: `runtime.PHPConfig{Version, MemoryMB, UploadMB, PostMB, ExecutionSeconds, InputVars, DisplayErrors}`
- Produces: `runtime.ValidatePHPConfig` and `runtime.RenderPool`
- Adds operations: `php.ensure_pool`, `php.activate_pool`, `php.install_extension`

- [ ] **Step 1: Write bounded-setting and shared-impact tests**

```go
func TestPHPConfigRequiresPostAtLeastUpload(t *testing.T) {
    err := ValidatePHPConfig(PHPConfig{Version: "8.4", UploadMB: 128, PostMB: 64})
    if !errors.Is(err, ErrPostBelowUpload) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/runtime ./internal/agent -run 'TestPHPConfigRequiresPostAtLeastUpload|TestExtensionImpactListsEvery84Site' -v`  
Expected: FAIL because PHP runtime packages are absent.

- [ ] **Step 3: Implement pool rendering and explicit package jobs**

Allow only PHP 8.3, 8.4, and 8.5 with default 8.4. Derive pool user/socket names in the agent, render bounded settings, run the version-specific FPM config test, atomically activate, and health-check the selected site. Extension installation takes an allowlisted package key and returns every affected site before enqueue; no per-site OPcache-clear endpoint is added.

- [ ] **Step 4: Verify config goldens and rollback**

Run: `go test -race ./internal/runtime ./internal/agent ./internal/web`  
Expected: PASS for all supported versions, unsupported/EOL input, package lock serialization, and rollback on pool health failure.

- [ ] **Step 5: Commit**

```bash
git add internal/runtime internal/agent internal/web web/templates/site_runtime.html
git commit -m "feat: add per site php runtime management"
```

### Task 5: Provisioning jobs, approved site UI, and reversible disable

**Files:**
- Create: `internal/sites/provision.go`
- Create: `internal/sites/provision_test.go`
- Create: `internal/web/site_handlers.go`
- Create: `internal/web/site_handlers_test.go`
- Create: `web/templates/sites.html`
- Create: `web/templates/site_create.html`
- Create: `web/templates/site_overview.html`
- Create: `web/static/site-create.js`
- Modify: `internal/web/app.go`

**Interfaces:**
- Consumes: `jobs.Manager`, `sites.Repository`, `domains.Service`, `runtime` validators, and `agentapi.Client`
- Produces: `sites.BuildProvisionJob(input CreateInput) jobs.Definition`
- Produces: `sites.BuildSetEnabledJob(siteID string, enabled bool) jobs.Definition`

- [ ] **Step 1: Write failure-resume and ownership tests**

```go
func TestProvisionRetryDoesNotDuplicateLinuxUser(t *testing.T) {
    env := failingProvisionEnv(t, "nginx.activate")
    id := env.RunAndRetry()
    if got := env.AgentCalls(id, "site.ensure_identity"); got != 1 { t.Fatalf("calls=%d", got) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/sites ./internal/web -run 'TestProvisionRetryDoesNotDuplicateLinuxUser|TestDisableKeepsManagedResources|TestReEnableRunsHealthCheck' -v`  
Expected: FAIL because orchestration and pages are absent.

- [ ] **Step 3: Implement vertical provisioning and enable/disable flows**

Build ordered idempotent steps for identity, directories, optional PHP pool, Nginx, local HTTP health, DNS, certificate, HTTPS activation, and final state. Render the approved Sites table, creation wizard, Site Overview, Domains & SSL, and Runtime pages. Disable removes the owned active Nginx link and stops owned workers without deleting resources; re-enable validates configuration and health before returning the site to `active`.

- [ ] **Step 4: Verify the slice end to end**

Run: `go test -race ./internal/sites ./internal/domains ./internal/runtime ./internal/web && go test ./...`  
Expected: PASS. VM check: create Static, PHP, and Reverse Proxy sites; inject a bad Nginx config; confirm the previous site stays available; disable and safely re-enable one site.

- [ ] **Step 5: Commit**

```bash
git add internal/sites internal/web web/templates web/static/site-create.js
git commit -m "feat: add guarded site provisioning and disable"
```
