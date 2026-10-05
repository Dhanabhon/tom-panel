package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/config"
)

const testMasterKey = "0123456789abcdef0123456789abcdef"

func doctorEnvironment(t *testing.T) (*Doctor, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte(testMasterKey), 0o400); err != nil {
		t.Fatal(err)
	}
	sitesEnabled := filepath.Join(dir, "sites-enabled")
	if err := os.MkdirAll(sitesEnabled, 0o755); err != nil {
		t.Fatal(err)
	}
	nginx := filepath.Join(dir, "nginx")
	if err := os.WriteFile(nginx, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ufw := filepath.Join(dir, "ufw")
	if err := os.WriteFile(ufw, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	systemdRun := filepath.Join(dir, "systemd")
	if err := os.MkdirAll(systemdRun, 0o755); err != nil {
		t.Fatal(err)
	}
	doctor := NewDoctor(config.Config{
		StateDir:    dir,
		AgentSocket: filepath.Join(dir, "agent.sock"),
	})
	doctor.NginxBinary = nginx
	doctor.SitesEnabled = sitesEnabled
	doctor.UFWBinary = ufw
	doctor.SystemdRun = systemdRun
	return doctor, dir
}

func findCheck(output string, name string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	return ""
}

func TestDoctorReportsHealthyHost(t *testing.T) {
	doctor, _ := doctorEnvironment(t)
	doctor.AgentCall = func(context.Context, string, any, any) error { return nil }
	var output bytes.Buffer
	if failed := doctor.Run(context.Background(), &output); failed != 0 {
		t.Fatalf("healthy host reported %d failures:\n%s", failed, output.String())
	}
	for _, name := range []string{"master key", "state directory", "database", "privileged agent", "nginx", "firewall (ufw)", "systemd"} {
		line := findCheck(output.String(), name)
		if !strings.HasPrefix(line, "[PASS]") {
			t.Fatalf("check %q not passing: %q", name, line)
		}
	}
	if !strings.Contains(output.String(), "8 migration(s) applied") {
		t.Fatalf("migration count missing:\n%s", output.String())
	}
}

func TestDoctorFlagsFailingAgentWithHint(t *testing.T) {
	doctor, _ := doctorEnvironment(t)
	doctor.AgentCall = func(context.Context, string, any, any) error { return errors.New("dial failed") }
	var output bytes.Buffer
	if failed := doctor.Run(context.Background(), &output); failed == 0 {
		t.Fatal("failing agent not reported")
	}
	line := findCheck(output.String(), "privileged agent")
	if !strings.HasPrefix(line, "[FAIL]") || !strings.Contains(line, "dial failed") {
		t.Fatalf("agent line wrong: %q", line)
	}
	if !strings.Contains(output.String(), "tompanel-agent.service") {
		t.Fatal("agent failure hint missing")
	}
}

func TestDoctorFlagsMissingMasterKey(t *testing.T) {
	doctor, dir := doctorEnvironment(t)
	doctor.AgentCall = func(context.Context, string, any, any) error { return nil }
	if err := os.Remove(filepath.Join(dir, "master.key")); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if failed := doctor.Run(context.Background(), &output); failed == 0 {
		t.Fatal("missing key not reported")
	}
	if !strings.Contains(output.String(), "hint: the key is created by the package postinst") {
		t.Fatalf("recovery hint missing:\n%s", output.String())
	}
}

func TestDoctorWarnsOnLooseKeyPermissions(t *testing.T) {
	doctor, dir := doctorEnvironment(t)
	doctor.AgentCall = func(context.Context, string, any, any) error { return nil }
	keyPath := filepath.Join(dir, "master.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	doctor.Run(context.Background(), &output)
	line := findCheck(output.String(), "master key")
	if !strings.HasPrefix(line, "[PASS]") || !strings.Contains(line, "0400") {
		t.Fatalf("loose key perms not annotated: %q", line)
	}
	if !strings.Contains(output.String(), "hint: chmod 0400") {
		t.Fatal("chmod hint missing")
	}
}

func TestDoctorFlagsMissingBinaries(t *testing.T) {
	doctor, _ := doctorEnvironment(t)
	doctor.AgentCall = func(context.Context, string, any, any) error { return nil }
	doctor.UFWBinary = filepath.Join(t.TempDir(), "absent")
	var output bytes.Buffer
	if failed := doctor.Run(context.Background(), &output); failed == 0 {
		t.Fatal("missing ufw not reported")
	}
	if !strings.Contains(findCheck(output.String(), "firewall (ufw)"), "[FAIL]") {
		t.Fatal("ufw line not failing")
	}
}
