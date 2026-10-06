package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFile resolves a repository-relative fixture and fails on read error.
func readFile(t *testing.T, relative string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return string(content)
}

func TestUnitsKeepWebDaemonUnprivileged(t *testing.T) {
	unit := readFile(t, "packaging/systemd/tompanel.service")
	for _, want := range []string{"User=tompanel", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict", "CapabilityBoundingSet="} {
		if !strings.Contains(unit, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(unit, "User=root") {
		t.Fatal("web daemon must not run as root")
	}
	// A Requires= on a unit we never ship bricks the panel at boot.
	if strings.Contains(unit, "tompanel-agent.socket") {
		t.Fatal("panel unit must not depend on a nonexistent socket unit")
	}
}

func TestAgentUnitIsHardened(t *testing.T) {
	unit := readFile(t, "packaging/systemd/tompanel-agent.service")
	for _, want := range []string{"NoNewPrivileges=true", "ProtectHome=true", "RestrictAddressFamilies=AF_UNIX", "CapabilityBoundingSet="} {
		if !strings.Contains(unit, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if !strings.Contains(unit, "CapabilityBoundingSet=CAP_CHOWN") {
		t.Fatal("agent capability set must be minimal but functional")
	}
}

func TestTmpfilesCreateRuntimeStateWithOwnership(t *testing.T) {
	conf := readFile(t, "packaging/tmpfiles/tompanel.conf")
	for _, want := range []string{
		"d /run/tompanel 0750 tompanel tompanel",
		"d /var/lib/tompanel 0750 tompanel tompanel",
		"d /var/backups/tompanel 0750 tompanel tompanel",
		"d /srv/tompanel/sites 0755 root root",
		"d /srv/tompanel/quarantine 0700 root root",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing tmpfiles rule %q", want)
		}
	}
}

func TestPostinstNeverRegeneratesExistingMasterKey(t *testing.T) {
	script := readFile(t, "packaging/debian/postinst")
	if !strings.Contains(script, "if [ ! -f /etc/tompanel/master.key ]") {
		t.Fatal("master key creation must be guarded")
	}
	if !strings.Contains(script, "chmod 0400 /etc/tompanel/master.key") {
		t.Fatal("master key must be created mode 0400")
	}
}

func TestInstallerRefusesForeignStacksAndKeepsSSHFirst(t *testing.T) {
	script := readFile(t, "scripts/install.sh")
	for _, want := range []string{
		"only Ubuntu Server 24.04 LTS is supported",
		"only AMD64 is supported",
		"/etc/tompanel already exists",
		"ufw allow OpenSSH",
		"ufw --force enable",
		"TOMPANEL_PHP_PPA",
		"PANEL_DOMAIN",
		"PANEL_PORT",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer missing %q", want)
		}
	}
	sshIndex := strings.Index(script, "ufw allow OpenSSH")
	firewallIndex := strings.Index(script, "ufw --force enable")
	if sshIndex < 0 || firewallIndex < 0 || sshIndex > firewallIndex {
		t.Fatal("OpenSSH must be allowed before UFW enables")
	}
}

func TestUninstallPreservesDataWithoutExactConfirmation(t *testing.T) {
	script := readFile(t, "scripts/uninstall.sh")
	if !strings.Contains(script, "TOMPANEL_PURGE_SITES=/srv/tompanel") {
		t.Fatal("site removal requires exact path confirmation")
	}
	if strings.Contains(script, "rm -rf /srv/tompanel\n") && !strings.Contains(script, "TOMPANEL_PURGE_SITES") {
		t.Fatal("unconditional site removal found")
	}
}

func TestLogrotateKeepsBoundedHistory(t *testing.T) {
	conf := readFile(t, "packaging/logrotate/tompanel")
	if !strings.Contains(conf, "rotate 8") || !strings.Contains(conf, "size 50M") {
		t.Fatal("log rotation must stay bounded")
	}
}

func TestBootstrapVerifiesBeforeInstall(t *testing.T) {
	script := readFile(t, "scripts/bootstrap.sh")
	for _, want := range []string{
		"sha256sum -c",
		"checksum mismatch; refusing to install",
		"releases/latest",
		"--offline",
		"--check",
		"[ -t 1 ]",
		"setup-url",
		"ssh -L 8080:127.0.0.1:8080",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("bootstrap missing %q", want)
		}
	}
}

func TestInstallerSupportsPreflightCheck(t *testing.T) {
	script := readFile(t, "scripts/install.sh")
	checkIndex := strings.Index(script, "TOMPANEL_CHECK")
	swapIndex := strings.Index(script, "creating a 2 GB swapfile")
	if checkIndex < 0 || swapIndex < 0 {
		t.Fatal("installer lacks preflight mode")
	}
	if checkIndex > swapIndex {
		t.Fatal("preflight exit must run before any host change (swap)")
	}
	if !strings.Contains(script, "preflight OK") {
		t.Fatal("preflight success message missing")
	}
}

func TestChangelogDocumentsFirstRelease(t *testing.T) {
	changelog := readFile(t, "CHANGELOG.md")
	for _, want := range []string{
		"## [0.1.0]",
		"Early access",
		"[0.1.0]: https://github.com/Dhanabhon/tom-panel/releases/tag/v0.1.0",
	} {
		if !strings.Contains(changelog, want) {
			t.Fatalf("changelog missing %q", want)
		}
	}
}
