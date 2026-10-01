package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

func testStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath, keyPath := filepath.Join(dir, "state.db"), filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), dbPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return database, filepath.Join(dir, "state.db")
}

const accessSiteID = "11111111111111111111111111111111"

func mustSeedSite(t *testing.T, database *store.Store, siteID string) {
	t.Helper()
	err := database.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO admins(id, username, password_hash, created_at, updated_at)
			VALUES (1, 'admin', x'00', 0, 0)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(context.Background(), `INSERT INTO sites(id, kind, state, primary_domain, https_port, public, created_at, updated_at)
			VALUES (?, 'php', 'active', 'example.test', 443, 0, 0, 0)`, siteID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

type capturedAgentCall struct {
	operation string
	input     map[string]any
}

func captureAgent(resultFor map[string]map[string]any, failFor map[string]bool) (func(context.Context, string, any, any) error, *[]capturedAgentCall) {
	calls := &[]capturedAgentCall{}
	return func(ctx context.Context, operation string, input, output any) error {
		call := capturedAgentCall{operation: operation}
		if encoded, err := json.Marshal(input); err == nil {
			var decoded map[string]any
			if json.Unmarshal(encoded, &decoded) == nil {
				call.input = decoded
			}
		}
		*calls = append(*calls, call)
		if failFor != nil && failFor[operation] {
			return context.DeadlineExceeded
		}
		if resultFor != nil && resultFor[operation] != nil {
			encoded, _ := json.Marshal(resultFor[operation])
			_ = json.Unmarshal(encoded, output)
		}
		return nil
	}, calls
}

func TestAccessEnableGrantsAndRecords(t *testing.T) {
	database, _ := testStore(t)
	mustSeedSite(t, database, accessSiteID)
	agent, calls := captureAgent(nil, nil)
	service := NewAccessService(database, agent)
	account, err := service.Enable(context.Background(), accessSiteID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if account.Username != "tp_"+accessSiteID[:16] || account.State != AccountActive {
		t.Fatalf("unexpected account: %+v", account)
	}
	operations := make([]string, 0, len(*calls))
	for _, call := range *calls {
		operations = append(operations, call.operation)
	}
	if strings.Join(operations, ",") != "sftp.ensure_account,file.grant_panel_access" {
		t.Fatalf("unexpected agent sequence: %v", operations)
	}
	again, _, err := service.Get(context.Background(), accessSiteID)
	if err != nil || again.ID != account.ID || again.State != AccountActive {
		t.Fatalf("account not persisted: %+v %v", again, err)
	}
}

func TestAccessRotateKeepsSecretOutOfStorage(t *testing.T) {
	database, databasePath := testStore(t)
	mustSeedSite(t, database, accessSiteID)
	agent, _ := captureAgent(nil, nil)
	service := NewAccessService(database, agent)
	if _, err := service.Enable(context.Background(), accessSiteID, nil); err != nil {
		t.Fatal(err)
	}
	password, err := service.RotatePassword(context.Background(), accessSiteID, &AuditEvent{AdminID: 1, Action: "sftp.password.rotated"})
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != passwordLength {
		t.Fatalf("password length: %d", len(password))
	}
	account, _, err := service.Get(context.Background(), accessSiteID)
	if err != nil || !account.PasswordSet {
		t.Fatalf("password state not recorded: %+v %v", account, err)
	}
	var stored strings.Builder
	for _, suffix := range []string{"", "-wal", "-shm"} {
		content, err := os.ReadFile(databasePath + suffix)
		if err == nil {
			stored.Write(content)
		}
	}
	if strings.Contains(stored.String(), password) {
		t.Fatal("rotated password persisted to disk")
	}
}

func TestAccessRotateRequiresEnabledAccount(t *testing.T) {
	database, _ := testStore(t)
	agent, calls := captureAgent(nil, nil)
	service := NewAccessService(database, agent)
	if _, err := service.RotatePassword(context.Background(), accessSiteID, nil); err == nil {
		t.Fatal("rotation without an account succeeded")
	}
	if len(*calls) != 0 {
		t.Fatal("rotation reached the agent without an account")
	}
}

func TestAccessKeyLifecycleRecordsFingerprints(t *testing.T) {
	database, _ := testStore(t)
	mustSeedSite(t, database, accessSiteID)
	const fingerprint = "SHA256:abc123"
	const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPmVLVRU2lLx2nfBBpzTKzXaJ5XqlUCZ1p0TCBhWQn2f panel@example"
	agent, _ := captureAgent(map[string]map[string]any{"sftp.add_key": {"fingerprint": fingerprint}}, nil)
	service := NewAccessService(database, agent)
	if _, err := service.Enable(context.Background(), accessSiteID, nil); err != nil {
		t.Fatal(err)
	}
	key, err := service.AddKey(context.Background(), accessSiteID, publicKey, &AuditEvent{AdminID: 1, Action: "sftp.key.added"})
	if err != nil {
		t.Fatal(err)
	}
	if key.Fingerprint != fingerprint || key.KeyType != "ssh-ed25519" {
		t.Fatalf("unexpected key record: %+v", key)
	}
	_, keys, err := service.Get(context.Background(), accessSiteID)
	if err != nil || len(keys) != 1 || keys[0].Fingerprint != fingerprint {
		t.Fatalf("key not persisted: %+v %v", keys, err)
	}
	if err := service.RemoveKey(context.Background(), accessSiteID, fingerprint, &AuditEvent{AdminID: 1, Action: "sftp.key.removed"}); err != nil {
		t.Fatal(err)
	}
	_, keys, err = service.Get(context.Background(), accessSiteID)
	if err != nil || len(keys) != 0 {
		t.Fatalf("key removal failed: %+v %v", keys, err)
	}
}

func TestAccessDisableBlocksRotation(t *testing.T) {
	database, _ := testStore(t)
	mustSeedSite(t, database, accessSiteID)
	agent, _ := captureAgent(nil, nil)
	service := NewAccessService(database, agent)
	if _, err := service.Enable(context.Background(), accessSiteID, nil); err != nil {
		t.Fatal(err)
	}
	if err := service.Disable(context.Background(), accessSiteID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RotatePassword(context.Background(), accessSiteID, nil); err == nil {
		t.Fatal("rotation succeeded on a disabled account")
	}
}
