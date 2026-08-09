package jobs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactorRemovesSecrets(t *testing.T) {
	r := NewRedactor("registered-value")
	input := "access_token=abc123 client_secret: hunter2 database_password=four Authorization: Bearer bearer-value Authorization: Basic basic-value registered-value"
	got := r.Redact(input)
	for _, secret := range []string{"abc123", "hunter2", "four", "bearer-value", "basic-value", "registered-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output contains %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("redacted output = %q", got)
	}
}

func TestRedactorRemovesMultiwordCredentialThroughLine(t *testing.T) {
	r := NewRedactor()
	got := r.Redact("request password=correct horse battery staple\nordinary diagnostic text")
	if strings.Contains(got, "horse battery staple") {
		t.Fatalf("redacted output leaked credential suffix: %q", got)
	}
	if !strings.Contains(got, "request password=[REDACTED]") || !strings.Contains(got, "ordinary diagnostic text") {
		t.Fatalf("redacted output lost useful non-secret text: %q", got)
	}
}

func TestRedactorPreservesLargeJSONNumbers(t *testing.T) {
	r := NewRedactor()
	got := r.RedactJSON(json.RawMessage(`{"sequence":900719925474099312345678901234567890,"message":"ordinary"}`))
	if !strings.Contains(string(got), `900719925474099312345678901234567890`) {
		t.Fatalf("large integer changed during redaction: %s", got)
	}
	if !strings.Contains(string(got), `"message":"ordinary"`) {
		t.Fatalf("ordinary JSON text changed during redaction: %s", got)
	}
}

func TestRedactorRemovesStructuredCredentialNames(t *testing.T) {
	r := NewRedactor()
	got := r.RedactJSON([]byte(`{"access_token":"one","client_secret":"two","authorization":"Basic dGhyZWU=","database_password":"four","oauthAccessToken":"five","webhook-secret":"six"}`))
	for _, secret := range []string{"one", "two", "dGhyZWU=", "four", "five", "six"} {
		if strings.Contains(string(got), secret) {
			t.Fatalf("structured output contains %q: %s", secret, got)
		}
	}
}

func TestRedactorRemovesCredentialFromTopLevelJSONString(t *testing.T) {
	r := NewRedactor()
	got := r.RedactJSON(json.RawMessage(`"ordinary text; accessToken=top-level-value"`))
	if !json.Valid(got) {
		t.Fatalf("redacted value is not valid JSON: %s", got)
	}
	var decoded string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != "ordinary text; accessToken=[REDACTED]" {
		t.Fatalf("redacted string = %q", decoded)
	}
}

func TestRedactorRemovesCamelCasePrefixedCredentialNames(t *testing.T) {
	r := NewRedactor()
	got := r.Redact("ordinary=value accessToken=access-value clientSecret: client-value databasePassword=database-value")
	for _, secret := range []string{"access-value", "client-value", "database-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output contains %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "ordinary=value") {
		t.Fatalf("redaction removed non-secret text: %q", got)
	}
}

func TestRedactorIgnoresEmptyRegisteredSecret(t *testing.T) {
	r := NewRedactor("")
	if got := r.Redact("ordinary output"); got != "ordinary output" {
		t.Fatalf("output = %q", got)
	}
}
