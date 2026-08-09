# TomPanel Foundation and Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Boot a private TomPanel instance with secure administrator login, durable SQLite state, a peer-verified root agent, one durable demo job, and the approved Dashboard shell.

**Architecture:** Three binaries share small concrete packages. `tompaneld` owns product state and never performs privileged work; `tompanel-agent` dispatches a closed set of typed operations; `tompanel` performs local diagnostics and offline credential reset.

**Tech Stack:** Go 1.26.x, `net/http`, `html/template`, `embed`, `modernc.org/sqlite`, `golang.org/x/crypto/argon2`, Unix sockets, SSE, vanilla CSS/JavaScript.

## Global Constraints

- Ubuntu Server 24.04 LTS AMD64 only.
- No shell-command endpoint, generic operation registry, ORM, web framework, frontend framework, or runtime dependency injection.
- Administrator username/password changes and TOTP reset are interactive CLI-only after bootstrap.
- Secrets are encrypted per field and excluded from application, job, and audit logs.
- The first setup URL is single-use, private, random, and expires after 15 minutes.

---

## Test fixture contract

Test helpers are local to their named `_test.go` file: `writeConfig` writes supplied text under `t.TempDir`; `openTestStore` creates a 32-byte key and migrated temporary SQLite database; `newTestServer` wires an in-memory connection with fixed peer credentials; `seededAuth` returns a migrated store with one admin; `login` returns a valid session ID; `resetPassword` invokes the CLI service directly. Job helpers `pass`, `failOnce`, `newTestManager`, `enqueueAndRun`, `retryAndRun`, and `assertAttempts` register a test job kind, persist its immutable input, and assert recorded step-attempt counts.

### Task 1: Go module, configuration, and daemon health

**Files:**
- Create: `go.mod`
- Create: `cmd/tompaneld/main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `internal/web/app.go`
- Create: `internal/web/app_test.go`

**Interfaces:**
- Produces: `config.Load(path string) (config.Config, error)`
- Produces: `web.New(config.Config) (*web.App, error)` and `(*web.App).Handler() http.Handler`

- [ ] **Step 1: Write configuration tests**

```go
func TestLoadRejectsNonLoopbackListen(t *testing.T) {
    path := writeConfig(t, "listen = \"0.0.0.0:8080\"\nstate_dir = \"/var/lib/tompanel\"\nagent_socket = \"/run/tompanel/agent.sock\"\n")
    _, err := Load(path)
    if err == nil || !strings.Contains(err.Error(), "loopback") { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `go test ./internal/config -run TestLoadRejectsNonLoopbackListen -v`  
Expected: FAIL because `Load` does not exist.

- [ ] **Step 3: Implement the minimum parser and health handler**

Use a small line-based TOML subset for the three bootstrap keys; reject unknown keys and require `net.ParseIP(host).IsLoopback()`. `GET /healthz` returns `200` and `{"status":"ok"}`; every other route returns `404` until later tasks register it.

```go
type Config struct { Listen, StateDir, AgentSocket string }
func Load(path string) (Config, error)
func New(cfg config.Config) (*App, error)
func (a *App) Handler() http.Handler
```

- [ ] **Step 4: Verify the slice**

Run: `go test ./internal/config ./internal/web && go vet ./cmd/tompaneld/... ./internal/config/... ./internal/web/...`  
Expected: PASS; `go run ./cmd/tompaneld -config ./testdata/config.toml` listens only on loopback.

- [ ] **Step 5: Commit**

```bash
git add go.mod cmd/tompaneld internal/config internal/web
git commit -m "feat: bootstrap private tompanel daemon"
```

### Task 2: SQLite migrations, master-key encryption, and repositories

**Files:**
- Modify: `go.mod`
- Create: `migrations/0001_core.sql`
- Create: `internal/store/store.go`
- Create: `internal/store/migrate.go`
- Create: `internal/store/crypto.go`
- Create: `internal/store/store_test.go`
- Create: `internal/store/crypto_test.go`

**Interfaces:**
- Consumes: `config.Config.StateDir`
- Produces: `store.Open(ctx context.Context, dbPath, keyPath string) (*store.Store, error)`
- Produces: `(*store.Store).Encrypt(plain, aad []byte) ([]byte, error)` and `Decrypt(ciphertext, aad []byte) ([]byte, error)`
- Produces: transaction helper `(*store.Store).Tx(ctx, func(*sql.Tx) error) error`

- [ ] **Step 1: Write migration and encryption tests**

```go
func TestCiphertextCannotMoveBetweenFields(t *testing.T) {
    s := openTestStore(t)
    blob, _ := s.Encrypt([]byte("token"), []byte("integrations:1:token"))
    if _, err := s.Decrypt(blob, []byte("admins:1:secret")); err == nil { t.Fatal("AAD mismatch accepted") }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `go test ./internal/store -run 'TestCiphertextCannotMoveBetweenFields|TestMigrationsAreAtomic' -v`  
Expected: FAIL because the store is absent.

- [ ] **Step 3: Implement the core schema and concrete store**

Add `modernc.org/sqlite`. Configure `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`, and `synchronous=FULL`. Create the core tables `admins`, `sessions`, `jobs`, `job_steps`, `audit_events`, `managed_resources`, and `settings`. Use AES-256-GCM from the standard library with random nonces and per-field AAD; require a 32-byte `0400` master key.

- [ ] **Step 4: Verify migration crash safety**

Run: `go test ./internal/store -count=10 && go test -race ./internal/store`  
Expected: PASS; a deliberately failing migration leaves `schema_migrations` unchanged.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum migrations internal/store
git commit -m "feat: add durable encrypted sqlite store"
```

### Task 3: Versioned agent protocol and peer-verified Unix socket

**Files:**
- Create: `internal/agentapi/protocol.go`
- Create: `internal/agentapi/client.go`
- Create: `internal/agentapi/client_test.go`
- Create: `internal/agent/server.go`
- Create: `internal/agent/peer_linux.go`
- Create: `internal/agent/operations.go`
- Create: `internal/agent/server_test.go`
- Create: `cmd/tompanel-agent/main.go`

**Interfaces:**
- Produces: `agentapi.Request{Version uint16, ID string, Operation string, Payload json.RawMessage}`
- Produces: `agentapi.Response{Version uint16, ID string, Result json.RawMessage, Error *agentapi.Error}`
- Produces: `(*agentapi.Client).Call(ctx context.Context, operation string, input, output any) error`
- Produces closed operations: `system.inspect` and `job.demo` only in this slice.

- [ ] **Step 1: Write authorization and framing tests**

```go
func TestRejectsUnexpectedPeerUID(t *testing.T) {
    srv := newTestServer(t, PeerCredentials{UID: 1002}, 1001)
    err := srv.ServeOne(context.Background())
    if !errors.Is(err, ErrUnauthorizedPeer) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `go test ./internal/agent ./internal/agentapi -run 'TestRejectsUnexpectedPeerUID|TestRejectsOversizedFrame' -v`  
Expected: FAIL because protocol and server are absent.

- [ ] **Step 3: Implement bounded JSON framing and closed dispatch**

Prefix each JSON message with a 4-byte big-endian length, cap frames at 1 MiB, set read/write deadlines from the request context, read Linux `SO_PEERCRED`, and dispatch with a `switch req.Operation`. Unknown operations return `operation_not_allowed`; never pass an operation or payload through a shell.

- [ ] **Step 4: Verify socket permissions and cancellation**

Run: `go test -race ./internal/agent ./internal/agentapi`  
Expected: PASS for wrong UID, wrong version, oversized frame, timeout, malformed JSON, and allowed demo operation.

- [ ] **Step 5: Commit**

```bash
git add cmd/tompanel-agent internal/agent internal/agentapi
git commit -m "feat: add peer verified typed agent channel"
```

### Task 4: Bootstrap, login, sessions, TOTP, CSRF, and offline recovery

**Files:**
- Modify: `go.mod`
- Create: `internal/auth/password.go`
- Create: `internal/auth/totp.go`
- Create: `internal/auth/service.go`
- Create: `internal/auth/middleware.go`
- Create: `internal/auth/service_test.go`
- Create: `internal/auth/middleware_test.go`
- Create: `internal/web/auth_handlers.go`
- Create: `internal/web/auth_handlers_test.go`
- Create: `cmd/tompanel/main.go`
- Create: `internal/cli/admin.go`
- Create: `internal/cli/admin_test.go`

**Interfaces:**
- Consumes: `*store.Store`
- Produces: `auth.New(store *store.Store, now func() time.Time) *auth.Service`
- Produces: `CreateSetupToken`, `CompleteSetup`, `Authenticate`, `VerifyTOTP`, `RequireSession`, `RequireCSRF`, and `RequireStepUp`
- Produces CLI commands: `admin reset-password`, `admin set-username`, `admin reset-totp`

- [ ] **Step 1: Write security boundary tests**

```go
func TestCredentialResetInvalidatesEverySession(t *testing.T) {
    svc, adminID := seededAuth(t)
    session := login(t, svc)
    resetPassword(t, svc, adminID, "a new long passphrase")
    if svc.SessionValid(context.Background(), session) { t.Fatal("old session survived reset") }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `go test ./internal/auth ./internal/cli ./internal/web -run 'TestCredentialResetInvalidatesEverySession|TestCSRFRejectsCrossOrigin|TestLoginDoesNotRevealUsername' -v`  
Expected: FAIL because auth services are absent.

- [ ] **Step 3: Implement the approved authentication flow**

Use Argon2id with measured parameters capped for a 2 GB server, constant-shape login errors, hashed random session IDs, host-only `Secure; HttpOnly; SameSite=Strict` cookies, 30-minute idle and 12-hour absolute expiry, synchronizer CSRF tokens plus Origin checks, six-digit TOTP with a narrow skew window, and a five-minute step-up record. CLI reads secrets with terminal echo disabled and never accepts them as flags.

- [ ] **Step 4: Verify HTTP and CLI behavior**

Run: `go test -race ./internal/auth ./internal/cli ./internal/web`  
Expected: PASS for setup expiry/single use, throttling bounds, Unicode passwords, TOTP, session expiry, CSRF, step-up, and reset invalidation.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum cmd/tompanel internal/auth internal/cli internal/web
git commit -m "feat: add single admin authentication and recovery"
```

### Task 5: Durable jobs, SSE, audit log, and approved shell

**Files:**
- Create: `internal/jobs/model.go`
- Create: `internal/jobs/manager.go`
- Create: `internal/jobs/redact.go`
- Create: `internal/jobs/manager_test.go`
- Create: `internal/jobs/redact_test.go`
- Create: `internal/web/jobs_handlers.go`
- Create: `internal/web/dashboard_handlers.go`
- Create: `internal/web/dashboard_handlers_test.go`
- Create: `web/templates/layout.html`
- Create: `web/templates/login.html`
- Create: `web/templates/dashboard.html`
- Create: `web/static/app.css`
- Create: `web/static/app.js`
- Modify: `internal/web/app.go`

**Interfaces:**
- Consumes: `*store.Store`, `*auth.Service`, and `*agentapi.Client`
- Produces: `jobs.Definition{Kind string, Input json.RawMessage, Steps []jobs.Step}` and `jobs.Step{Key string, Run func(context.Context) (json.RawMessage, error)}`
- Produces: `jobs.Manager.Register(kind string, build func(json.RawMessage) (jobs.Definition, error)) error`, `Enqueue(ctx context.Context, def jobs.Definition) (string, error)`, `ResumeIncomplete(ctx context.Context) error`, `RunNext(ctx context.Context) error`, `Cancel(ctx context.Context, jobID string) error`, and `Subscribe(jobID string) (<-chan jobs.Event, func())`

- [ ] **Step 1: Write transition and redaction tests**

```go
func TestRetryStartsAtFirstIncompleteStep(t *testing.T) {
    m := newTestManager(t, []Step{pass("one"), failOnce("two"), pass("three")})
    id := enqueueAndRun(t, m)
    retryAndRun(t, m, id)
    assertAttempts(t, id, map[string]int{"one": 1, "two": 2, "three": 1})
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `go test ./internal/jobs ./internal/web -run 'TestRetryStartsAtFirstIncompleteStep|TestRedactorRemovesSecrets|TestJobSSERequiresSession' -v`  
Expected: FAIL because the manager and handlers are absent.

- [ ] **Step 3: Implement job persistence and server-rendered UI**

Persist the job kind and immutable input so `ResumeIncomplete` can rebuild steps after a daemon restart. Persist `queued/running/succeeded/failed/cancelling/cancelled`; commit step state before broadcasting SSE; cancel only between steps; bound subscriber buffers; redact registered secret values and common credential patterns. Recreate the approved layout, login, TOTP, Dashboard, and job progress behavior with shared templates and embedded static files.

- [ ] **Step 4: Verify the foundation acceptance slice**

Run: `go test -race ./internal/jobs ./internal/web && go test ./...`  
Expected: PASS. Manual check: bootstrap through an SSH tunnel, log in with TOTP, start the demo job, reload the browser, and observe the same durable job state.

- [ ] **Step 5: Commit**

```bash
git add internal/jobs internal/web web
git commit -m "feat: add durable jobs and operations first shell"
```
