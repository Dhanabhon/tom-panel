package jobs

import (
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

func TestRedactorRemovesStructuredCredentialNames(t *testing.T) {
	r := NewRedactor()
	got := r.RedactJSON([]byte(`{"access_token":"one","client_secret":"two","authorization":"Basic dGhyZWU=","database_password":"four","oauthAccessToken":"five","webhook-secret":"six"}`))
	for _, secret := range []string{"one", "two", "dGhyZWU=", "four", "five", "six"} {
		if strings.Contains(string(got), secret) {
			t.Fatalf("structured output contains %q: %s", secret, got)
		}
	}
}

func TestRedactorIgnoresEmptyRegisteredSecret(t *testing.T) {
	r := NewRedactor("")
	if got := r.Redact("ordinary output"); got != "ordinary output" {
		t.Fatalf("output = %q", got)
	}
}
