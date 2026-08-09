# TomPanel Applications, Data, and Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add confined File Manager/SFTP, site-scoped MariaDB/phpMyAdmin, and guarded WordPress and Laravel lifecycle workflows to active sites.

**Architecture:** Web handlers validate product intent and enqueue jobs. The agent derives all filesystem paths, database identifiers, service names, and command arguments from stored site IDs and allowlisted recipes; application secrets travel through stdin or protected files.

**Tech Stack:** Plans 1-2 APIs, Go `os.Root`, OpenSSH `internal-sftp`, MariaDB 10.11 Unix socket, verified phpMyAdmin archive, signed WP-CLI, Composer 2, Git, optional Node.js 24 LTS, optional Redis ACLs.

## Global Constraints

- File operations remain inside a pre-opened site root; reject absolute paths, `..`, magic links, devices, and symlink escapes.
- SFTP accounts have no shell, forwarding, tunneling, or agent access.
- MariaDB is local-only; TomPanel stores no MariaDB root password.
- phpMyAdmin is private by default; public modes require HTTPS, rate limits, and independent HTTP Basic Auth.
- WordPress uses Nginx page cache and optional Redis; LiteSpeed is excluded.
- Laravel accepts only the fixed deployment pipeline and no custom command or shell hook.

---

## Test fixture contract

`testRoot` opens a temporary `os.Root`; `maliciousTarWithSymlink` returns an in-memory tar containing a symlink entry. `rotationEnv` creates a temporary database service with fake application health behavior; `healthFails` selects a failing health check. `buildWPInstallCall` returns the exact argument array/stdin payload without executing it; `testInstallInput` includes a known sentinel password. `renderSitePage` serves the named route through `httptest`; `staticSite` inserts a Static site fixture.

### Task 1: Confined File Manager, Trash, archives, and SFTP

**Files:**
- Create: `migrations/0003_access.sql`
- Create: `internal/files/service.go`
- Create: `internal/files/archive.go`
- Create: `internal/files/service_test.go`
- Create: `internal/files/archive_test.go`
- Create: `internal/agent/file_ops.go`
- Create: `internal/agent/sftp_ops.go`
- Create: `internal/agent/file_ops_test.go`
- Create: `internal/agent/sftp_ops_test.go`
- Create: `internal/web/file_handlers.go`
- Create: `internal/web/file_handlers_test.go`
- Create: `web/templates/site_files.html`
- Create: `web/static/file-manager.js`

**Interfaces:**
- Produces: `files.Service.List`, `ReadText`, `WriteText`, `Upload`, `Download`, `Create`, `Rename`, `Copy`, `Move`, `Trash`, `RestoreTrash`, `Archive`, `Extract`
- Adds operations: `sftp.ensure_account`, `sftp.rotate_password`, `sftp.add_key`, `sftp.remove_key`
- Produces: `files.Limits{MaxUploadBytes, MaxTextBytes, MaxArchiveFiles, MaxExpandedBytes}`

- [ ] **Step 1: Write confinement and archive-abuse tests**

```go
func TestExtractRejectsSymlinkEntry(t *testing.T) {
    root := testRoot(t)
    err := Extract(root, maliciousTarWithSymlink(t), Limits{MaxArchiveFiles: 100, MaxExpandedBytes: 1 << 20})
    if !errors.Is(err, ErrUnsafeArchiveEntry) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/files ./internal/agent -run 'TestExtractRejectsSymlinkEntry|TestOpenRejectsParentTraversal|TestSFTPDisablesForwarding' -v`  
Expected: FAIL because file and SFTP packages are absent.

- [ ] **Step 3: Implement confined operations and recoverable deletion**

Open `/srv/tompanel/sites/<derived-id>` once with `os.OpenRoot`; pass only validated relative paths. Stream uploads to a temporary same-filesystem file with size/hash limits, then rename. Validate every archive header before extraction and stop before disk guards. Move deletes to `.tompanel-trash/<random-id>` with metadata and expiry. Render forced `internal-sftp` Match blocks from typed account records and validate `sshd -t` before activation.

- [ ] **Step 4: Verify the complete access boundary**

Run: `go test -race ./internal/files ./internal/agent ./internal/web`  
Expected: PASS for traversal, symlink races, devices, oversized uploads, archive bombs, Trash restore, password rotation, key removal, and no-forwarding configuration.

- [ ] **Step 5: Commit**

```bash
git add migrations/0003_access.sql internal/files internal/agent internal/web web/templates/site_files.html web/static/file-manager.js
git commit -m "feat: add confined files and sftp access"
```

### Task 2: MariaDB resources, credential rotation, and phpMyAdmin

**Files:**
- Create: `migrations/0004_databases.sql`
- Create: `internal/databases/service.go`
- Create: `internal/databases/names.go`
- Create: `internal/databases/service_test.go`
- Create: `internal/agent/mariadb_ops.go`
- Create: `internal/agent/phpmyadmin_ops.go`
- Create: `internal/agent/mariadb_ops_test.go`
- Create: `internal/agent/phpmyadmin_ops_test.go`
- Create: `internal/web/database_handlers.go`
- Create: `internal/web/database_handlers_test.go`
- Create: `web/templates/site_databases.html`

**Interfaces:**
- Produces: `databases.Service.Create`, `Backup`, `Restore`, `RotateCredential`, `Delete`, `ConfigurePHPMyAdmin`
- Adds operations: `mariadb.ensure_database`, `mariadb.rotate_user`, `mariadb.dump`, `mariadb.restore`, `phpmyadmin.install`, `phpmyadmin.activate`, `phpmyadmin.disable`
- Produces: `databases.PHPMyAdminMode` constants `private`, `public_subdomain`, `public_port`

- [ ] **Step 1: Write grant, rotation, and endpoint tests**

```go
func TestRotationKeepsOldCredentialUntilHealthCheck(t *testing.T) {
    env := rotationEnv(t, healthFails())
    if err := env.Rotate("db1", true); err == nil { t.Fatal("rotation unexpectedly passed") }
    if !env.OldCredentialWorks() { t.Fatal("old credential retired before health check") }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/databases ./internal/agent -run 'TestRotationKeepsOldCredentialUntilHealthCheck|TestGrantCannotEscapeSite|TestPrivatePHPMyAdminOpensNoFirewall' -v`  
Expected: FAIL because database operations are absent.

- [ ] **Step 3: Implement Unix-socket administration and verified phpMyAdmin**

Derive database/user names from site ID plus validated suffixes. Send SQL through the MariaDB Unix-socket driver with identifier quoting and explicit database-scoped grants. Creation and rotation require step-up and return the new secret once in a non-cacheable response; later reads expose only configured state. Rotation creates a second credential, updates a managed app config when requested, health-checks, then removes the old credential. Verify phpMyAdmin upstream PGP/SHA256 before atomic shared installation; private mode binds loopback, public modes add Nginx rate limits and generated Basic Auth before database login.

- [ ] **Step 4: Verify database and endpoint recovery**

Run: `go test -race ./internal/databases ./internal/agent ./internal/web`  
Expected: PASS for wrong ownership, dump/restore failure, rotation rollback, public port collision, Basic Auth, private disable, and externally owned Nginx/UFW resources.

- [ ] **Step 5: Commit**

```bash
git add migrations/0004_databases.sql internal/databases internal/agent internal/web web/templates/site_databases.html
git commit -m "feat: add site databases and phpmyadmin"
```

### Task 3: WordPress install, updates, cron, and cache

**Files:**
- Create: `migrations/0005_applications.sql`
- Create: `internal/apps/wordpress.go`
- Create: `internal/apps/wordpress_test.go`
- Create: `internal/agent/wordpress_ops.go`
- Create: `internal/agent/redis_ops.go`
- Create: `internal/agent/wordpress_ops_test.go`
- Create: `internal/web/wordpress_handlers.go`
- Create: `internal/web/wordpress_handlers_test.go`
- Create: `web/templates/site_wordpress.html`
- Modify: `web/templates/site_create.html`

**Interfaces:**
- Produces: `apps.WordPressInstallInput` and `apps.BuildWordPressInstallJob`
- Produces: `apps.WordPressPolicy{MinorCore, MajorCore, Plugins, Themes bool}`
- Adds operations: `wordpress.install`, `wordpress.update_core`, `wordpress.configure_cron`, `wordpress.configure_page_cache`, `redis.ensure_site_acl`, `redis.remove_site_acl`, `wordpress.clear_cache`

- [ ] **Step 1: Write secret, cache-scope, and guarded-update tests**

```go
func TestWordPressSecretsNeverEnterArguments(t *testing.T) {
    call := buildWPInstallCall(testInstallInput())
    for _, arg := range call.Args { if strings.Contains(arg, "generated-password") { t.Fatal("secret in argv") } }
    if !bytes.Contains(call.Stdin, []byte("generated-password")) { t.Fatal("secret missing from protected input") }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/apps ./internal/agent -run 'TestWordPressSecretsNeverEnterArguments|TestClearCacheTouchesOnlySelectedSite|TestFailedUpdateRestoresBackup' -v`  
Expected: FAIL because WordPress operations are absent.

- [ ] **Step 3: Implement verified WP-CLI and fixed WordPress flows**

Verify the pinned WP-CLI Phar signature before installation. Pass administrator/database secrets through stdin or mode-`0600` files, generate secure salts, configure HTTPS, and enable security/minor updates by default. Major/plugin/theme updates remain independent. System cron replaces request-driven WP-Cron when selected. Page cache uses the selected site's directory; Redis uses a unique ACL and prefix; never call `FLUSHALL`.

- [ ] **Step 4: Verify install and management pages**

Run: `go test -race ./internal/apps ./internal/agent ./internal/web`  
Expected: PASS for install retry, update backup/maintenance/health/rollback, policy changes, independent cache removal, and redacted job/audit output.

- [ ] **Step 5: Commit**

```bash
git add migrations/0005_applications.sql internal/apps internal/agent internal/web web/templates/site_wordpress.html web/templates/site_create.html
git commit -m "feat: add guarded wordpress lifecycle"
```

### Task 4: Laravel install and atomic deployment

**Files:**
- Create: `internal/apps/laravel.go`
- Create: `internal/apps/laravel_test.go`
- Create: `internal/agent/laravel_ops.go`
- Create: `internal/agent/laravel_ops_test.go`
- Create: `internal/web/laravel_handlers.go`
- Create: `internal/web/laravel_handlers_test.go`
- Create: `web/templates/site_laravel.html`
- Create: `web/static/laravel-deploy.js`
- Modify: `web/templates/site_create.html`

**Interfaces:**
- Produces: `apps.LaravelInstallInput`, `apps.LaravelDeployInput`, `apps.BuildLaravelInstallJob`, `apps.BuildLaravelDeployJob`
- Adds operations: `laravel.checkout`, `laravel.composer_install`, `laravel.node_build`, `laravel.migrate`, `laravel.optimize`, `laravel.activate_release`, `laravel.ensure_workers`

- [ ] **Step 1: Write transport, lockfile, migration, and activation tests**

```go
func TestLaravelRejectsRepositoryWithLocalTransport(t *testing.T) {
    err := ValidateLaravelRepo("file:///tmp/repo")
    if !errors.Is(err, ErrUnsafeGitTransport) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/apps ./internal/agent -run 'TestLaravelRejectsRepositoryWithLocalTransport|TestNodeBuildRequiresLockfile|TestFailedHealthCheckKeepsCurrentRelease' -v`  
Expected: FAIL because Laravel operations are absent.

- [ ] **Step 3: Implement the fixed production pipeline**

Pin one Laravel major in release data. Allow HTTPS or SSH Git only; generate one deploy key per private repository; disable file/external-helper transports. Execute argument arrays for checkout, `composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader`, optional Node 24 `npm ci` and `npm run build`, separately confirmed `php artisan migrate --force`, optimization, local health check, then atomic `current` symlink activation. Persist `.env`, deploy keys, and shared writable storage outside releases.

- [ ] **Step 4: Verify deployment and worker lifecycle**

Run: `go test -race ./internal/apps ./internal/agent ./internal/web`  
Expected: PASS for private-key permissions, missing lockfile, migration refusal, failed build, failed health check, current-release preservation, and managed queue/scheduler units.

- [ ] **Step 5: Commit**

```bash
git add internal/apps internal/agent internal/web web/templates/site_laravel.html web/templates/site_create.html web/static/laravel-deploy.js
git commit -m "feat: add fixed laravel deployment pipeline"
```

### Task 5: Integrate approved site navigation and application states

**Files:**
- Modify: `internal/web/site_handlers.go`
- Modify: `internal/web/app.go`
- Modify: `web/templates/layout.html`
- Modify: `web/templates/site_overview.html`
- Create: `internal/web/site_navigation_test.go`
- Create: `tests/integration/applications_test.go`

**Interfaces:**
- Consumes every service produced in Tasks 1-4.
- Produces exact site navigation: Overview, Domains & SSL, Files & Access, Runtime, Databases, Applications, Backups, Logs.

- [ ] **Step 1: Write route and unavailable-control tests**

```go
func TestStaticSiteHidesApplicationMutationControls(t *testing.T) {
    body := renderSitePage(t, staticSite(), "/sites/s1/applications")
    if strings.Contains(body, "Install WordPress") || strings.Contains(body, "Deploy Laravel") { t.Fatal("misleading controls rendered") }
}
```

- [ ] **Step 2: Confirm tests fail**

Run: `go test ./internal/web ./tests/integration -run 'TestStaticSiteHidesApplicationMutationControls|TestWordPressFlow|TestLaravelFlow' -v`  
Expected: FAIL because route integration is incomplete.

- [ ] **Step 3: Wire view models and exact approved surfaces**

Keep handlers server-rendered; JavaScript only enhances dialogs, SSE, file interactions, and progress. Render correct empty/loading/failure states from persisted data, hide unsupported actions by site kind and installed dependencies, and route every mutation through CSRF plus a job or required step-up confirmation.

- [ ] **Step 4: Verify the full applications/data slice**

Run: `go test -race ./internal/files ./internal/databases ./internal/apps ./internal/web && go test ./tests/integration -run 'TestWordPressFlow|TestLaravelFlow|TestSFTPBoundary|TestDatabaseBoundary' -v`  
Expected: PASS with no secret in captured arguments, HTTP responses, SSE, jobs, or audit events.

- [ ] **Step 5: Commit**

```bash
git add internal/web web/templates tests/integration/applications_test.go
git commit -m "feat: integrate managed application workspace"
```
