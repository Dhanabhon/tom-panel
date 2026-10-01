package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRefusesUnmanagedUnit(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("runner must not be reached for unmanaged units")
		return nil, nil
	}
	if err := validateManagedUnit("ssh.service"); err == nil {
		t.Fatal("ssh accepted")
	}
	if _, err := inspectService(context.Background(), serviceUnitInput{Unit: "tompaneld.service"}, run); err == nil {
		t.Fatal("panel unit accepted")
	}
	if err := serviceAction(context.Background(), serviceUnitInput{Unit: "nginx.service;reboot"}, "restart", run); err == nil {
		t.Fatal("injected unit accepted")
	}
}

func TestInspectParsesSystemctlShow(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "/usr/bin/systemctl" || !strings.Contains(strings.Join(args, " "), "show") {
			return nil, errors.New("unexpected call")
		}
		return []byte("ActiveState=active\nSubState=running\n"), nil
	}
	result, err := inspectService(context.Background(), serviceUnitInput{Unit: "nginx.service"}, run)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Active || result.State != "active/running" {
		t.Fatalf("state parse failed: %+v", result)
	}
}

func TestServiceActionRunsSystemctl(t *testing.T) {
	var seen string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		seen = name + " " + strings.Join(args, " ")
		return nil, nil
	}
	if err := serviceAction(context.Background(), serviceUnitInput{Unit: "mariadb.service"}, "restart", run); err != nil {
		t.Fatal(err)
	}
	if seen != "/usr/bin/systemctl restart mariadb.service --no-pager" {
		t.Fatalf("unexpected command: %q", seen)
	}
}

func TestLogReadFiltersAndBounds(t *testing.T) {
	base := t.TempDir()
	original := siteRootPath
	siteRootPath = base
	t.Cleanup(func() { siteRootPath = original })
	logDir := filepath.Join(base, dbTestSiteID, "storage", "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	var builder strings.Builder
	for i := 0; i < 1000; i++ {
		builder.WriteString("2026-10-01 ERROR production something broke\n")
		builder.WriteString("2026-10-01 INFO noise\n")
	}
	if err := os.WriteFile(filepath.Join(logDir, "laravel.log"), []byte(builder.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	result, err := readLog(context.Background(), logReadInput{
		SiteID: dbTestSiteID, Source: "app", Search: "error", MaxLines: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Lines) != 10 {
		t.Fatalf("lines = %d, want bounded 10", len(result.Lines))
	}
	for _, line := range result.Lines {
		if !strings.Contains(line, "ERROR") {
			t.Fatalf("unfiltered line returned: %s", line)
		}
	}
	if _, err := readLog(context.Background(), logReadInput{SiteID: dbTestSiteID, Source: "auditd"}); err == nil {
		t.Fatal("unsupported source accepted")
	}
	if _, err := readLog(context.Background(), logReadInput{SiteID: "../evil", Source: "app"}); err == nil {
		t.Fatal("unsafe site id accepted")
	}
}
