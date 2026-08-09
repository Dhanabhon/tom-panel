package jobs

import (
	"strings"
	"testing"
)

func TestRedactorRemovesSecrets(t *testing.T) {
	r := NewRedactor("registered-value")
	input := "token=abc123 password: hunter2 Authorization: Bearer bearer-value registered-value"
	got := r.Redact(input)
	for _, secret := range []string{"abc123", "hunter2", "bearer-value", "registered-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output contains %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("redacted output = %q", got)
	}
}

func TestRedactorIgnoresEmptyRegisteredSecret(t *testing.T) {
	r := NewRedactor("")
	if got := r.Redact("ordinary output"); got != "ordinary output" {
		t.Fatalf("output = %q", got)
	}
}
