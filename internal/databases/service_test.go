package databases

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

const rotationSiteID = "22222222222222222222222222222222"

type rotationEnv struct {
	service *Service
	database *store.Store
	rotateCalls []map[string]any
	failVerify bool
	appUpdates []string
	databasePath string
}

func newRotationEnv(t *testing.T, failVerify bool) *rotationEnv {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(dir, "state.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, created_at, updated_at)
			VALUES (?, 'php', 'active', 'rotate.example.test', 443, 0, 0, 0)`, rotationSiteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	env := &rotationEnv{database: database, failVerify: failVerify, databasePath: filepath.Join(dir, "state.db")}
	caller := func(ctx context.Context, operation string, input, output any) error {
		if operation == "mariadb.rotate_user" {
			encoded, _ := json.Marshal(input)
			var decoded map[string]any
			_ = json.Unmarshal(encoded, &decoded)
			env.rotateCalls = append(env.rotateCalls, decoded)
			return nil
		}
		if operation == "mariadb.verify_credential" && failVerify {
			return errors.New("replacement credential rejected")
		}
		if operation == "mariadb.dump" {
			encoded, _ := json.Marshal(map[string]any{
				"path":   "/var/backups/tompanel/databases/" + rotationSiteID + "/dump.sql",
				"size":   1234,
				"sha256": strings.Repeat("a", 64),
			})
			_ = json.Unmarshal(encoded, output)
		}
		return nil
	}
	env.service = NewService(database, caller)
	env.service.SetAppConfigUpdater(func(ctx context.Context, siteID, dbName, username, password string) error {
		env.appUpdates = append(env.appUpdates, username)
		return nil
	})
	return env
}

func (e *rotationEnv) seed(t *testing.T) Database {
	t.Helper()
	record, _, err := e.service.Create(context.Background(), rotationSiteID, "shop")
	if err != nil {
		t.Fatal(err)
	}
	e.rotateCalls = nil
	return record
}

func (e *rotationEnv) OldCredentialWorks() bool {
	for _, call := range e.rotateCalls {
		if retire, ok := call["retire_username"].(string); ok && retire != "" {
			return false
		}
	}
	return true
}

func (e *rotationEnv) Rotate(suffix string, updateApp bool) error {
	_, err := e.service.RotateCredential(context.Background(), rotationSiteID, suffix, updateApp)
	return err
}

func TestRotationKeepsOldCredentialUntilHealthCheck(t *testing.T) {
	env := newRotationEnv(t, true)
	env.seed(t)
	if err := env.Rotate("shop", true); err == nil {
		t.Fatal("rotation unexpectedly passed")
	}
	if !env.OldCredentialWorks() {
		t.Fatal("old credential retired before health check")
	}
	items, err := env.service.List(context.Background(), rotationSiteID)
	if err != nil || len(items) != 1 || items[0].ActiveGeneration != 1 {
		t.Fatalf("failed rotation changed persisted state: %+v %v", items, err)
	}
}

func TestRotationSucceedsAfterVerification(t *testing.T) {
	env := newRotationEnv(t, false)
	env.seed(t)
	if err := env.Rotate("shop", true); err != nil {
		t.Fatal(err)
	}
	if env.OldCredentialWorks() {
		t.Fatal("old credential never retired after a healthy rotation")
	}
	last := env.rotateCalls[len(env.rotateCalls)-1]
	if last["retire_username"] != "tp_"+rotationSiteID[:16]+"_u1" {
		t.Fatalf("retired the wrong user: %+v", last)
	}
	if len(env.appUpdates) != 1 || env.appUpdates[0] != "tp_"+rotationSiteID[:16]+"_u2" {
		t.Fatalf("app config not updated: %v", env.appUpdates)
	}
	items, _ := env.service.List(context.Background(), rotationSiteID)
	if items[0].ActiveGeneration != 2 {
		t.Fatalf("generation not persisted: %+v", items[0])
	}
}

func TestRotationWithoutAppUpdateSkipsHook(t *testing.T) {
	env := newRotationEnv(t, false)
	env.seed(t)
	if err := env.Rotate("shop", false); err != nil {
		t.Fatal(err)
	}
	if len(env.appUpdates) != 0 {
		t.Fatalf("app config updated despite opt-out: %v", env.appUpdates)
	}
}

func TestRotationNeverPersistsPassword(t *testing.T) {
	env := newRotationEnv(t, false)
	env.seed(t)
	credential, err := env.service.RotateCredential(context.Background(), rotationSiteID, "shop", false)
	if err != nil {
		t.Fatal(err)
	}
	var stored strings.Builder
	for _, suffix := range []string{"", "-wal", "-shm"} {
		content, err := os.ReadFile(env.databasePath + suffix)
		if err == nil {
			stored.Write(content)
		}
	}
	if strings.Contains(stored.String(), credential.Password) {
		t.Fatal("rotated password persisted to disk")
	}
	if len(credential.Password) < 20 {
		t.Fatalf("password too short: %q", credential.Password)
	}
}

func TestCreateRejectsUnsafeSuffixesAndDuplicates(t *testing.T) {
	env := newRotationEnv(t, false)
	for _, suffix := range []string{"", "has-dash", "UPPER", "_leading", "trailing_", strings.Repeat("a", 20)} {
		if _, _, err := env.service.Create(context.Background(), rotationSiteID, suffix); err == nil {
			t.Fatalf("accepted unsafe suffix %q", suffix)
		}
	}
	if _, _, err := env.service.Create(context.Background(), "../evil", "shop"); err == nil {
		t.Fatal("accepted unsafe site ID")
	}
	if _, _, err := env.service.Create(context.Background(), rotationSiteID, "shop"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.service.Create(context.Background(), rotationSiteID, "shop"); !errors.Is(err, ErrSuffixTaken) {
		t.Fatalf("duplicate suffix: %v", err)
	}
}

func TestBackupRestoreDeleteLifecycle(t *testing.T) {
	env := newRotationEnv(t, false)
	env.seed(t)
	backup, err := env.service.Backup(context.Background(), rotationSiteID, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if backup.SHA256 == "" || backup.AgentPath == "" {
		t.Fatalf("backup metadata incomplete: %+v", backup)
	}
	if err := env.service.Restore(context.Background(), rotationSiteID, "shop", backup.ID); err != nil {
		t.Fatal(err)
	}
	if err := env.service.Restore(context.Background(), rotationSiteID, "shop", "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrBackupNotFound) {
		t.Fatalf("unknown backup: %v", err)
	}
	if err := env.service.Delete(context.Background(), rotationSiteID, "shop"); err != nil {
		t.Fatal(err)
	}
	if items, _ := env.service.List(context.Background(), rotationSiteID); len(items) != 0 {
		t.Fatalf("database survived delete: %+v", items)
	}
}

func TestPHPMyAdminPrivateModeAllocatesLoopbackPort(t *testing.T) {
	env := newRotationEnv(t, false)
	endpoint, credential, err := env.service.ConfigurePHPMyAdmin(context.Background(), rotationSiteID, ModePrivate, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Port < privatePortFirst || endpoint.Port > privatePortLast {
		t.Fatalf("private port outside loopback range: %d", endpoint.Port)
	}
	if endpoint.BasicAuthSet || credential.Password != "" {
		t.Fatalf("private mode must not mint basic auth: %+v %+v", endpoint, credential)
	}
	stored, err := env.service.Endpoint(context.Background(), rotationSiteID)
	if err != nil || stored.Port != endpoint.Port {
		t.Fatalf("endpoint not persisted: %+v %v", stored, err)
	}
}

func TestPHPMyAdminPortCollisionDetected(t *testing.T) {
	env := newRotationEnv(t, false)
	if _, _, err := env.service.ConfigurePHPMyAdmin(context.Background(), rotationSiteID, ModePublicPort, "db.example.test", 8443); err != nil {
		t.Fatal(err)
	}
	other := "33333333333333333333333333333333"
	if err := env.database.Tx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, created_at, updated_at)
			VALUES (?, 'php', 'active', 'other.example.test', 443, 0, 0, 0)`, other)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.service.ConfigurePHPMyAdmin(context.Background(), other, ModePublicPort, "db2.example.test", 8443); !errors.Is(err, ErrPortUnavailable) {
		t.Fatalf("collision accepted: %v", err)
	}
}

func TestPHPMyAdminDisableRemovesEndpoint(t *testing.T) {
	env := newRotationEnv(t, false)
	if _, _, err := env.service.ConfigurePHPMyAdmin(context.Background(), rotationSiteID, ModePublicSubdomain, "db.example.test", 0); err != nil {
		t.Fatal(err)
	}
	if err := env.service.DisablePHPMyAdmin(context.Background(), rotationSiteID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.service.Endpoint(context.Background(), rotationSiteID); !errors.Is(err, ErrEndpointNotFound) {
		t.Fatalf("endpoint survived disable: %v", err)
	}
}

func TestNameDerivationBounds(t *testing.T) {
	if name, err := DatabaseName(rotationSiteID, "shop"); err != nil || name != "tp_"+rotationSiteID[:16]+"_shop" {
		t.Fatalf("database name: %q %v", name, err)
	}
	if _, err := DatabaseName(rotationSiteID, "shop`; DROP"); err == nil {
		t.Fatal("injection accepted in suffix")
	}
	if user, err := UserName(rotationSiteID, 3); err != nil || user != "tp_"+rotationSiteID[:16]+"_u3" {
		t.Fatalf("user name: %q %v", user, err)
	}
	if _, err := UserName(rotationSiteID, 0); err == nil {
		t.Fatal("generation zero accepted")
	}
	if _, err := UserName(rotationSiteID, 100); err == nil {
		t.Fatal("generation overflow accepted")
	}
}
