package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestPHPConfigRequiresPostAtLeastUpload(t *testing.T) {
	err := ValidatePHPConfig(PHPConfig{Version: "8.4", MemoryMB: 256, UploadMB: 128, PostMB: 64, ExecutionSeconds: 60, InputVars: 1000})
	if !errors.Is(err, ErrPostBelowUpload) {
		t.Fatalf("ValidatePHPConfig() error = %v, want %v", err, ErrPostBelowUpload)
	}
}

func TestSaveConfigRejectsStaticSite(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(directory, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	site, err := sites.NewRepository(database).Create(context.Background(), sites.CreateInput{
		Kind: sites.KindStatic, PrimaryDomain: "static.example.com", HTTPPort: 80, HTTPSPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = NewService(database).SaveConfig(context.Background(), site.ID, DefaultPHPConfig("8.4"))
	if !errors.Is(err, ErrNotPHPSite) {
		t.Fatalf("SaveConfig() error = %v, want %v", err, ErrNotPHPSite)
	}
}

func TestPHPConfigRejectsUnsupportedVersion(t *testing.T) {
	err := ValidatePHPConfig(PHPConfig{Version: "8.2", MemoryMB: 256, UploadMB: 64, PostMB: 64, ExecutionSeconds: 60, InputVars: 1000})
	if !errors.Is(err, ErrUnsupportedPHP) {
		t.Fatalf("ValidatePHPConfig() error = %v, want %v", err, ErrUnsupportedPHP)
	}
}
