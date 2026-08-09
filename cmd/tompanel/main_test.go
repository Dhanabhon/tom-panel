package main

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/auth"
	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestSetupURLUsesFragmentAndCreatesUsableSingleUseToken(t *testing.T) {
	service := newSetupURLAuth(t)
	configPath := writeSetupURLConfig(t)
	var output bytes.Buffer
	err := runWith(context.Background(), []string{"-config", configPath, "setup-url"}, os.Stdin, &output, true,
		func(context.Context, config.Config) (*auth.Service, error) { return service, nil })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	setupURL, err := url.Parse(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	if setupURL.RawQuery != "" || !strings.HasPrefix(setupURL.Fragment, "token=") {
		t.Fatalf("setup URL = %q, want fragment token and no query", setupURL.String())
	}
	fragment, err := url.ParseQuery(setupURL.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CompleteSetup(context.Background(), fragment.Get("token"), "admin", "correct horse battery staple"); err != nil {
		t.Fatalf("setup URL token was unusable: %v", err)
	}
}

func TestSetupURLRefusesNonTerminalOutputBeforeCreatingToken(t *testing.T) {
	configPath := writeSetupURLConfig(t)
	var output bytes.Buffer
	opened := false
	err := runWith(context.Background(), []string{"-config", configPath, "setup-url"}, os.Stdin, &output, false,
		func(context.Context, config.Config) (*auth.Service, error) {
			opened = true
			return nil, nil
		})
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("error = %v", err)
	}
	if opened || output.Len() != 0 {
		t.Fatalf("non-terminal command opened store=%v output=%q", opened, output.String())
	}
}

func TestSetupURLRejectsTokenFlag(t *testing.T) {
	var output bytes.Buffer
	err := runWith(context.Background(), []string{"--token", "secret", "setup-url"}, os.Stdin, &output, true,
		func(context.Context, config.Config) (*auth.Service, error) { return nil, nil })
	if err == nil {
		t.Fatal("token flag was accepted")
	}
	if output.Len() != 0 {
		t.Fatalf("rejected token flag wrote output %q", output.String())
	}
}

func writeSetupURLConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	contents := "listen = \"127.0.0.1:8443\"\nstate_dir = \"/tmp/tompanel-test\"\nagent_socket = \"/tmp/tompanel-agent.sock\"\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newSetupURLAuth(t *testing.T) *auth.Service {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return auth.New(database, func() time.Time { return time.Unix(1_800_000_000, 0) })
}
