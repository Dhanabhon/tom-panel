package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsNonLoopbackListen(t *testing.T) {
	path := writeConfig(t, "listen = \"0.0.0.0:8080\"\nstate_dir = \"/var/lib/tompanel\"\nagent_socket = \"/run/tompanel/agent.sock\"\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("got %v", err)
	}
}

func TestLoad(t *testing.T) {
	path := writeConfig(t, "listen = \"127.0.0.1:8080\"\nstate_dir = \"/var/lib/tompanel\"\nagent_socket = \"/run/tompanel/agent.sock\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.StateDir != "/var/lib/tompanel" || cfg.AgentSocket != "/run/tompanel/agent.sock" {
		t.Fatalf("got %#v", cfg)
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	path := writeConfig(t, "listen = \"127.0.0.1:8080\"\nstate_dir = \"/var/lib/tompanel\"\nagent_socket = \"/run/tompanel/agent.sock\"\nextra = \"no\"\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("got %v", err)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
