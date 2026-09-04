package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPHPActivateRestoresPreviousPoolOnValidationFailure(t *testing.T) {
	const siteID = "0123456789abcdef0123456789abcdef"
	root := t.TempDir()
	active := filepath.Join(root, "tp_0123456789abcdef.conf")
	if err := os.WriteFile(active, []byte("; Managed by TomPanel: "+siteID+"\nold"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := activatePHPPool(context.Background(), phpPoolInput{
		SiteID: siteID, Version: "8.4", Config: "; Managed by TomPanel: " + siteID + "\nnew",
	}, root, func(context.Context, string, ...string) error { return errors.New("invalid pool") })
	if err == nil {
		t.Fatal("PHP-FPM validation failure was ignored")
	}
	got, _ := os.ReadFile(active)
	if string(got) != "; Managed by TomPanel: "+siteID+"\nold" {
		t.Fatalf("active pool = %q", got)
	}
}

func TestExtensionPayloadRejectsPackageName(t *testing.T) {
	var input phpExtensionInput
	err := decodeStrict(json.RawMessage(`{"version":"8.4","extension":"../../evil"}`), &input)
	if err == nil {
		err = validateExtension(input)
	}
	if err == nil {
		t.Fatal("path-shaped extension accepted")
	}
}

func TestEnsurePHPUsesVersionSpecificBinary(t *testing.T) {
	var name string
	err := ensurePHP(context.Background(), phpPoolInput{
		SiteID: "0123456789abcdef0123456789abcdef", Version: "8.4",
	}, func(_ context.Context, command string, _ ...string) error {
		name = command
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "/usr/sbin/php-fpm8.4" {
		t.Fatalf("binary = %q", name)
	}
}

func TestDisablePHPPoolRefusesUnmanagedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "tp_0123456789abcdef.conf"), []byte("administrator config"), 0o640); err != nil {
		t.Fatal(err)
	}
	err := disablePHPPool(context.Background(), phpPoolInput{
		SiteID: "0123456789abcdef0123456789abcdef", Version: "8.4",
	}, root, func(context.Context, string, ...string) error {
		t.Fatal("command ran for unmanaged pool")
		return nil
	})
	if err == nil {
		t.Fatal("unmanaged PHP-FPM pool was removed")
	}
}
