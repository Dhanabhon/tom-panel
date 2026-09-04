package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEnsureDirectoriesRejectsCallerPath(t *testing.T) {
	_, err := decodeEnsureDirectories(json.RawMessage(`{"site_id":"../../etc"}`))
	if err == nil {
		t.Fatal("path-shaped site ID accepted")
	}
}

func TestEnsureDirectoriesDerivesConfinedPaths(t *testing.T) {
	root := t.TempDir()
	result, err := ensureDirectories(context.Background(), json.RawMessage(`{"site_id":"0123456789abcdef0123456789abcdef"}`), root)
	if err != nil {
		t.Fatal(err)
	}
	if result.SiteRoot != "/srv/tompanel/sites/0123456789abcdef0123456789abcdef" || result.PublicRoot != result.SiteRoot+"/public" {
		t.Fatalf("ensureDirectories() = %#v", result)
	}
	info, err := os.Stat(filepath.Join(root, "0123456789abcdef0123456789abcdef", "public"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("public root is not a directory")
	}
}

func TestDirectoryOwnerUsesNginxGroup(t *testing.T) {
	uid, gid, err := directoryOwnerIDs("0123456789abcdef0123456789abcdef",
		func(name string) (*user.User, error) {
			if name != "tp_0123456789abcdef" {
				t.Fatalf("user lookup = %q", name)
			}
			return &user.User{Uid: "1001", Gid: "1001"}, nil
		},
		func(name string) (*user.Group, error) {
			if name != "www-data" {
				t.Fatalf("group lookup = %q", name)
			}
			return &user.Group{Gid: "33"}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1001 || gid != 33 {
		t.Fatalf("ownership = %d:%d, want 1001:33", uid, gid)
	}
}

func TestActivateNginxRestoresOwnedConfigWhenReloadFails(t *testing.T) {
	const marker = "# Managed by TomPanel: 0123456789abcdef0123456789abcdef\n"
	root := t.TempDir()
	active := filepath.Join(root, "tp-0123456789abcdef0123456789abcdef.conf")
	if err := os.WriteFile(active, []byte(marker+"old"), 0o640); err != nil {
		t.Fatal(err)
	}
	env := nginxEnvironment{
		root: root,
		run: func(_ context.Context, name string, args ...string) error {
			if name == "/usr/bin/systemctl" && len(args) == 2 && args[0] == "reload" {
				return errors.New("reload failed")
			}
			return nil
		},
		health: func(context.Context, string, int) error { return nil },
	}
	err := activateNginx(context.Background(), nginxActivateInput{
		SiteID: "0123456789abcdef0123456789abcdef", Config: marker + "new", HealthHost: "site.example.com", HealthPort: 443,
	}, env)
	if err == nil {
		t.Fatal("reload failure was ignored")
	}
	got, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != marker+"old" {
		t.Fatalf("active config = %q, want managed old config", got)
	}
}

func TestActivateNginxRefusesUnmanagedExistingConfig(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "tp-0123456789abcdef0123456789abcdef.conf")
	if err := os.WriteFile(active, []byte("administrator config"), 0o640); err != nil {
		t.Fatal(err)
	}
	env := nginxEnvironment{
		root: root,
		run: func(context.Context, string, ...string) error {
			t.Fatal("command ran for unmanaged config")
			return nil
		},
		health: func(context.Context, string, int) error { return nil },
	}
	err := activateNginx(context.Background(), nginxActivateInput{
		SiteID:     "0123456789abcdef0123456789abcdef",
		Config:     "# Managed by TomPanel: 0123456789abcdef0123456789abcdef\nnew",
		HealthHost: "site.example.com", HealthPort: 443,
	}, env)
	if err == nil {
		t.Fatal("unmanaged active config was overwritten")
	}
}

func TestActivateNginxRecoversDurableRollbackAfterInterruption(t *testing.T) {
	const marker = "# Managed by TomPanel: 0123456789abcdef0123456789abcdef\n"
	root := t.TempDir()
	name := "tp-0123456789abcdef0123456789abcdef.conf"
	if err := os.WriteFile(filepath.Join(root, name), []byte(marker+"interrupted"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "."+name+".rollback"), []byte(marker+"last-good"), 0o640); err != nil {
		t.Fatal(err)
	}
	env := nginxEnvironment{root: root,
		run:    func(context.Context, string, ...string) error { return errors.New("invalid candidate") },
		health: func(context.Context, string, int) error { return nil },
	}
	if err := activateNginx(context.Background(), nginxActivateInput{
		SiteID: "0123456789abcdef0123456789abcdef", Config: marker + "still-invalid",
		HealthHost: "site.example.com", HealthPort: 80,
	}, env); err == nil {
		t.Fatal("validation failure was ignored")
	}
	got, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != marker+"last-good" {
		t.Fatalf("active config = %q, want durable rollback", got)
	}
}

func TestRemoveUFWDeletesOnlyExactOwnedRule(t *testing.T) {
	const siteID = "0123456789abcdef0123456789abcdef"
	var calls [][]string
	err := removeOwnedUFWWith(context.Background(), ufwInput{SiteID: siteID, Port: 443},
		func(context.Context, string, ...string) ([]byte, error) {
			return []byte("[ 1] 443/tcp ALLOW IN Anywhere\n[ 2] 443/tcp ALLOW IN Anywhere # TomPanel:" + siteID + "\n"), nil
		},
		func(_ context.Context, name string, args ...string) error {
			calls = append(calls, append([]string{name}, args...))
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/usr/sbin/ufw", "--force", "delete", "2"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("delete calls = %#v, want %#v", calls, want)
	}
}
