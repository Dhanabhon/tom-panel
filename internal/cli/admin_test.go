package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestResetPasswordReadsSecretsInteractively(t *testing.T) {
	svc := seededCLIAuth(t)
	answers := []string{"a new long passphrase", "a new long passphrase"}
	read := func(string) (string, error) {
		answer := answers[0]
		answers = answers[1:]
		return answer, nil
	}
	var output bytes.Buffer
	commands := newAdminCommands(svc, read, nil, &output)
	if err := commands.Run(context.Background(), []string{"reset-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(context.Background(), "admin", "a new long passphrase", "192.0.2.10"); err != nil {
		t.Fatalf("new password was not usable: %v", err)
	}
	if strings.Contains(output.String(), "a new long passphrase") {
		t.Fatal("password was written to output")
	}
}

func TestAdminCommandsRejectSecretArguments(t *testing.T) {
	svc := seededCLIAuth(t)
	commands := newAdminCommands(svc, func(string) (string, error) {
		t.Fatal("secret reader should not be called")
		return "", nil
	}, nil, &bytes.Buffer{})
	if err := commands.Run(context.Background(), []string{"reset-password", "secret-on-command-line"}); err == nil {
		t.Fatal("password argument was accepted")
	}
}

func TestAdminCommandsRequireTerminalForSecrets(t *testing.T) {
	svc := seededCLIAuth(t)
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	commands := NewAdminCommands(svc, input, &bytes.Buffer{})
	err = commands.Run(context.Background(), []string{"reset-password"})
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("got %v", err)
	}
}

func TestSetUsernameInvalidatesSession(t *testing.T) {
	svc, recoveryCode := seededCLIAuthWithRecovery(t)
	session := recoveryLogin(t, svc, recoveryCode)
	commands := newAdminCommands(svc, nil, func(string) (string, error) { return "owner", nil }, &bytes.Buffer{})
	if err := commands.Run(context.Background(), []string{"set-username"}); err != nil {
		t.Fatal(err)
	}
	if svc.SessionValid(context.Background(), session.ID) {
		t.Fatal("old session survived username change")
	}
	if _, err := svc.Authenticate(context.Background(), "owner", "correct horse battery staple", "192.0.2.20"); err != nil {
		t.Fatalf("new username was not usable: %v", err)
	}
}

func TestResetTOTPInvalidatesSessionAndPrintsTenNewCodes(t *testing.T) {
	svc, recoveryCode := seededCLIAuthWithRecovery(t)
	session := recoveryLogin(t, svc, recoveryCode)
	var output bytes.Buffer
	commands := newAdminCommands(svc, nil, nil, &output)
	if err := commands.Run(context.Background(), []string{"reset-totp"}); err != nil {
		t.Fatal(err)
	}
	if svc.SessionValid(context.Background(), session.ID) {
		t.Fatal("old session survived TOTP reset")
	}
	if strings.Contains(output.String(), recoveryCode) {
		t.Fatal("old recovery code was printed")
	}
	if lines := strings.Count(output.String(), "-"); lines < 10 {
		t.Fatalf("output did not contain ten recovery codes: %q", output.String())
	}
}

func seededCLIAuth(t *testing.T) *auth.Service {
	t.Helper()
	svc, _ := seededCLIAuthWithRecovery(t)
	return svc
}

func seededCLIAuthWithRecovery(t *testing.T) (*auth.Service, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.New(s, func() time.Time { return time.Unix(1_800_000_000, 0) })
	token, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := svc.CompleteSetup(context.Background(), token, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return svc, enrollment.RecoveryCodes[0]
}

func recoveryLogin(t *testing.T, svc *auth.Service, code string) auth.Session {
	t.Helper()
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.21")
	if err != nil {
		t.Fatal(err)
	}
	session, err := svc.VerifyTOTP(context.Background(), challenge, code)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
