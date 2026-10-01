package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordedCommand struct {
	name string
	args []string
}

type fakeRunner struct {
	commands  []recordedCommand
	stdins    []string
	failNames map[string]int
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) error {
	f.commands = append(f.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	f.stdins = append(f.stdins, "")
	if f.failNames != nil && f.failNames[name] > 0 {
		f.failNames[name]--
		return errFor(name)
	}
	return nil
}

func (f *fakeRunner) runInput(_ context.Context, name string, stdin []byte, args ...string) error {
	f.commands = append(f.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	f.stdins = append(f.stdins, string(stdin))
	if f.failNames != nil && f.failNames[name] > 0 {
		f.failNames[name]--
		return errFor(name)
	}
	return nil
}

func errFor(name string) error {
	return &commandFailure{binary: name}
}

type commandFailure struct{ binary string }

func (c *commandFailure) Error() string { return "forced failure of " + c.binary }

func testSSHDEnvironment(t *testing.T, runner *fakeRunner) (sshdEnvironment, string) {
	t.Helper()
	dir := t.TempDir()
	return sshdEnvironment{root: dir, run: runner.run}, dir
}

const validTestSiteID = "0123456789abcdef0123456789abcdef"

func TestSFTPDisablesForwarding(t *testing.T) {
	env, dir := testSSHDEnvironment(t, &fakeRunner{})
	content, err := renderSFTPMatchBlock(validTestSiteID)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"# Managed by TomPanel: " + validTestSiteID,
		"Match User tp_" + validTestSiteID[:16],
		"ChrootDirectory /srv/tompanel/sites/" + validTestSiteID,
		"ForceCommand internal-sftp",
		"AllowTcpForwarding no",
		"X11Forwarding no",
		"AllowAgentForwarding no",
		"PermitTunnel no",
		"PermitTTY no",
		"PasswordAuthentication yes",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("match block missing %q:\n%s", required, content)
		}
	}
	if err := activateSFTPConfig(context.Background(), validTestSiteID, env); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(filepath.Join(dir, "tompanel-"+validTestSiteID+".conf"))
	if err != nil || string(written) != content {
		t.Fatalf("activated config mismatch: %q %v", written, err)
	}
}

func TestSFTPActivationValidatesBeforeCommit(t *testing.T) {
	runner := &fakeRunner{failNames: map[string]int{sshdBinary: 1}}
	env, dir := testSSHDEnvironment(t, runner)
	if err := activateSFTPConfig(context.Background(), validTestSiteID, env); err == nil {
		t.Fatal("activation succeeded despite sshd -t failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "tompanel-"+validTestSiteID+".conf")); !os.IsNotExist(err) {
		t.Fatal("invalid sshd config was committed")
	}
	if len(runner.commands) == 0 || runner.commands[0].name != sshdBinary {
		t.Fatalf("sshd -t was not the first command: %+v", runner.commands)
	}
}

func TestSFTPRefusesUnmanagedConfig(t *testing.T) {
	env, dir := testSSHDEnvironment(t, &fakeRunner{})
	name := filepath.Join(dir, "tompanel-"+validTestSiteID+".conf")
	if err := os.WriteFile(name, []byte("Match User someone-else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := activateSFTPConfig(context.Background(), validTestSiteID, env); err == nil {
		t.Fatal("replaced an unmanaged sshd config")
	}
}

func TestSFTPPasswordRotationNeverLeaksIntoArgv(t *testing.T) {
	runner := &fakeRunner{}
	if err := rotateSFTPPasswordWith(context.Background(), sftpPasswordInput{SiteID: validTestSiteID, Password: "generated-password-123"}, runner.runInput); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("expected one command, got %+v", runner.commands)
	}
	call := runner.commands[0]
	joined := strings.Join(call.args, " ")
	if strings.Contains(joined, "generated-password-123") {
		t.Fatalf("password leaked into argv: %q", joined)
	}
	if !strings.Contains(runner.stdins[0], "generated-password-123") {
		t.Fatalf("password missing from protected stdin: %q", runner.stdins[0])
	}
	if !strings.Contains(runner.stdins[0], "tp_"+validTestSiteID[:16]+":") {
		t.Fatalf("rotation payload missing derived username: %q", runner.stdins[0])
	}
}

func TestSFTPPasswordValidation(t *testing.T) {
	runner := &fakeRunner{}
	for _, password := range []string{"short", "with space123456", "with\newline12345", "has:colon12345678", strings.Repeat("a", 200)} {
		input := sftpPasswordInput{SiteID: validTestSiteID, Password: password}
		if err := rotateSFTPPasswordWith(context.Background(), input, runner.runInput); err == nil {
			t.Fatalf("accepted unsafe password %q", password)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("unsafe passwords still executed commands: %+v", runner.commands)
	}
}

const testEd25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPmVLVRU2lLx2nfBBpzTKzXaJ5XqlUCZ1p0TCBhWQn2f panel@example"

func sftpKeyRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, validTestSiteID), 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestSFTPKeyLifecycle(t *testing.T) {
	base := sftpKeyRoot(t)
	result, err := addSFTPKeyWith(context.Background(), sftpKeyInput{SiteID: validTestSiteID, PublicKey: testEd25519Key}, base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint format: %q", result.Fingerprint)
	}
	stored, err := os.ReadFile(filepath.Join(base, validTestSiteID, ".ssh", "authorized_keys"))
	if err != nil || !strings.HasPrefix(string(stored), testEd25519Key) {
		t.Fatalf("key not stored: %q %v", stored, err)
	}
	info, err := os.Stat(filepath.Join(base, validTestSiteID, ".ssh", "authorized_keys"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("authorized_keys mode: %v %v", info.Mode().Perm(), err)
	}
	if _, err := addSFTPKeyWith(context.Background(), sftpKeyInput{SiteID: validTestSiteID, PublicKey: testEd25519Key}, base); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if err := removeSFTPKeyWith(context.Background(), sftpKeyInput{SiteID: validTestSiteID, Fingerprint: result.Fingerprint}, base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, validTestSiteID, ".ssh")); !os.IsNotExist(err) {
		t.Fatal("empty authorized_keys scaffolding survived removal")
	}
}

func TestSFTPKeyRejectsUnsafeInput(t *testing.T) {
	base := sftpKeyRoot(t)
	for _, key := range []string{
		"",
		"garbage",
		"not-a-key AAAAC3NzaC1lZDI1NTE5AAAAIPmVLVRU2lLx2nfBBpzTKzXaJ5XqlUCZ1p0TCBhWQn2f c",
		testEd25519Key + "\nsecond-line",
		strings.Repeat("a", 9000),
	} {
		if _, err := addSFTPKeyWith(context.Background(), sftpKeyInput{SiteID: validTestSiteID, PublicKey: key}, base); err == nil {
			t.Fatalf("accepted unsafe key %q", key)
		}
	}
	if _, err := addSFTPKeyWith(context.Background(), sftpKeyInput{SiteID: "../evil", PublicKey: testEd25519Key}, base); err == nil {
		t.Fatal("accepted unsafe site ID")
	}
}

func TestGrantPanelAccessRunsScopedACL(t *testing.T) {
	runner := &fakeRunner{}
	if err := grantPanelAccessWith(context.Background(), validTestSiteID, "tompanel", "/srv/tompanel/sites", runner.run); err != nil {
		t.Fatal(err)
	}
	call := runner.commands[0]
	if call.name != setfaclBinary {
		t.Fatalf("expected setfacl, got %q", call.name)
	}
	joined := strings.Join(call.args, " ")
	if !strings.Contains(joined, "u:tompanel:rwX") || !strings.Contains(joined, "d:u:tompanel:rwX") {
		t.Fatalf("missing ACL grants: %q", joined)
	}
	if !strings.Contains(joined, "/srv/tompanel/sites/"+validTestSiteID) {
		t.Fatalf("ACL not scoped to the site root: %q", joined)
	}
	if strings.Contains(joined, "..") {
		t.Fatalf("traversal in ACL target: %q", joined)
	}
}
