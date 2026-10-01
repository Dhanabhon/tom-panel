# govulncheck record — 2026-10-02

Release-gate scan required by the MVP plan index ("record accepted findings
with exact dependency versions").

## Scan setup

| Item | Value |
|---|---|
| Scanner | govulncheck v1.8.0 (golang.org/x/vuln) |
| Vulnerability DB | vuln.go.dev, updated 2026-09-28 |
| Scope | `govulncheck ./...` (symbol-level) |
| Toolchain before | go1.26.0 |
| Toolchain after | **go1.26.6** |

## Findings and remediation

### Remediated in this scan: 31 standard-library vulnerabilities

The first run against go1.26.0 reported 31 vulnerabilities reachable from
TomPanel code, all in the Go standard library, with fixes spread across
go1.26.1 through go1.26.6 (net/url, html/template, crypto/tls, net/http,
encoding/xml, encoding/asn1, net, crypto/x509, and others). Example
reachability included `net/url.Parse` via `integrations.SaveS3` and
`http.Client.Do` via `domains.doCloudflare`.

**Remediation:** the module toolchain was raised to `go1.26.6`
(`go get toolchain@go1.26.6`) and the full test suite re-run green. The
follow-up scan reports **0 vulnerabilities affecting this code**.

### Accepted finding (module-level, not imported)

| Field | Value |
|---|---|
| Advisory | GO-2026-5932 |
| Module | golang.org/x/crypto |
| Version at scan | v0.57.0 (latest published; no fixed version exists — "Fixed in: N/A") |
| Issue | the `golang.org/x/crypto/openpgp` package is unmaintained and unsafe by design |

**Why accepted:** the advisory is module-scoped and fires for any dependency
on golang.org/x/crypto. TomPanel imports only `x/crypto/argon2`, `bcrypt`,
`blake2b`, `blowfish`, `chacha20{,poly1305}`, `curve25519`, and `hkdf`
(verified with `go list -deps ./... | grep openpgp` → zero matches); the
`openpgp` package is never imported and no code path reaches it. No fixed
version exists to upgrade to; the advisory is retired only by dropping the
module. Re-evaluate at the next release scan.

## Dependency versions at scan time

| Dependency | Version |
|---|---|
| golang.org/x/crypto | v0.57.0 |
| golang.org/x/sys | v0.48.0 |
| golang.org/x/term | v0.46.0 |
| filippo.io/age | v1.3.2 |
| github.com/aws/aws-sdk-go-v2/service/s3 | v1.114.0 |
| github.com/aws/smithy-go | v1.28.1 |
| github.com/go-sql-driver/mysql | v1.9.3 |
| modernc.org/sqlite | v1.56.0 |
| github.com/google/uuid | v1.6.0 |

## Verification after remediation

```
$ govulncheck ./...
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call
these vulnerabilities.   ← GO-2026-5932, accepted above

$ go test ./...   # green
$ go vet ./...    # green
```
