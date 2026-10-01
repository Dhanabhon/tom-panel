package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
)

const (
	sshdBinary         = "/usr/sbin/sshd"
	chpasswdBinary     = "/usr/sbin/chpasswd"
	sshdConfigRootPath = "/etc/ssh/sshd_config.d"
	panelUserName      = "tompanel"
)

var sshdMu sync.Mutex

type sshdEnvironment struct {
	root string
	run  func(context.Context, string, ...string) error
}

func defaultSSHDEnvironment() sshdEnvironment {
	return sshdEnvironment{root: sshdConfigRootPath, run: runCommand}
}

type sftpPasswordInput struct {
	SiteID   string `json:"site_id"`
	Password string `json:"password"`
}

type sftpKeyInput struct {
	SiteID      string `json:"site_id"`
	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type sftpKeyResult struct {
	Fingerprint string `json:"fingerprint"`
}

var allowedSSHKeyTypes = map[string]bool{
	"ssh-ed25519":        true,
	"ssh-rsa":            true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,
}

func renderSFTPMatchBlock(siteID string) (string, error) {
	if !validSiteID(siteID) {
		return "", errors.New("sftp.ensure_account payload is invalid")
	}
	username := "tp_" + siteID[:16]
	var builder strings.Builder
	builder.WriteString("# Managed by TomPanel: " + siteID + "\n")
	builder.WriteString("Match User " + username + "\n")
	builder.WriteString("    ChrootDirectory " + filepath.Join(siteRootPath, siteID) + "\n")
	builder.WriteString("    ForceCommand internal-sftp\n")
	builder.WriteString("    PasswordAuthentication yes\n")
	builder.WriteString("    PubkeyAuthentication yes\n")
	builder.WriteString("    AllowTcpForwarding no\n")
	builder.WriteString("    X11Forwarding no\n")
	builder.WriteString("    AllowAgentForwarding no\n")
	builder.WriteString("    PermitTunnel no\n")
	builder.WriteString("    PermitTTY no\n")
	return builder.String(), nil
}

// ensureSiteUser returns the site's dedicated system account, creating it on
// first use. The account never gets a shell or a home directory.
func ensureSiteUser(ctx context.Context, siteID string) (string, error) {
	if !validSiteID(siteID) {
		return "", errors.New("site identity payload is invalid")
	}
	name := "tp_" + siteID[:16]
	if _, err := user.Lookup(name); err == nil {
		return name, nil
	} else if !isUnknownUser(err) {
		return "", fmt.Errorf("lookup site identity: %w", err)
	}
	home := filepath.Join(siteRootPath, siteID)
	if err := runCommand(ctx, "/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", name); err != nil {
		return "", fmt.Errorf("create site identity: %w", err)
	}
	return name, nil
}

func isUnknownUser(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unknown user")
}

func activateSFTPConfig(ctx context.Context, siteID string, env sshdEnvironment) error {
	content, err := renderSFTPMatchBlock(siteID)
	if err != nil {
		return err
	}
	sshdMu.Lock()
	defer sshdMu.Unlock()

	root, err := os.OpenRoot(env.root)
	if err != nil {
		return fmt.Errorf("open sshd config root: %w", err)
	}
	defer root.Close()
	name := "tompanel-" + siteID + ".conf"
	marker := "# Managed by TomPanel: " + siteID + "\n"
	temporary := "." + name + ".candidate"
	backup := "." + name + ".rollback"
	old, readErr := root.ReadFile(backup)
	hadBackup := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read sshd rollback: %w", readErr)
	}
	hadOld := hadBackup && len(old) > 0
	if !hadBackup {
		old, readErr = root.ReadFile(name)
		hadOld = readErr == nil
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("read active sshd config: %w", readErr)
		}
	}
	if hadOld && !strings.HasPrefix(string(old), marker) {
		return errors.New("refusing to replace an unmanaged sshd config")
	}
	if !hadBackup {
		if err := root.WriteFile(backup, old, 0o600); err != nil {
			return fmt.Errorf("write sshd rollback: %w", err)
		}
	}
	if err := root.WriteFile(temporary, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write sshd candidate: %w", err)
	}
	defer root.Remove(temporary)
	if err := root.Rename(temporary, name); err != nil {
		return fmt.Errorf("activate sshd candidate: %w", err)
	}
	restore := func() error {
		var restoreErr error
		if hadOld {
			if err := root.WriteFile(temporary, old, 0o644); err != nil {
				return fmt.Errorf("write sshd rollback: %w", err)
			}
			if err := root.Rename(temporary, name); err != nil {
				return fmt.Errorf("activate sshd rollback: %w", err)
			}
		} else if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			restoreErr = fmt.Errorf("remove failed sshd config: %w", err)
		}
		if err := root.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("remove sshd rollback: %w", err))
		}
		return restoreErr
	}
	rollback := func() error {
		if err := restore(); err != nil {
			return err
		}
		if err := env.run(ctx, sshdBinary, "-t"); err != nil {
			return fmt.Errorf("validate sshd rollback: %w", err)
		}
		if err := env.run(ctx, "/usr/bin/systemctl", "reload", "ssh"); err != nil {
			return fmt.Errorf("reload sshd rollback: %w", err)
		}
		return nil
	}
	if err := env.run(ctx, sshdBinary, "-t"); err != nil {
		return errors.Join(fmt.Errorf("validate sshd config: %w", err), restore())
	}
	if err := env.run(ctx, "/usr/bin/systemctl", "reload", "ssh"); err != nil {
		return errors.Join(fmt.Errorf("reload sshd: %w", err), rollback())
	}
	if err := root.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove sshd rollback: %w", err)
	}
	return nil
}

func ensureSFTPAccount(ctx context.Context, siteID string) error {
	if _, err := ensureSiteUser(ctx, siteID); err != nil {
		return err
	}
	return activateSFTPConfig(ctx, siteID, defaultSSHDEnvironment())
}

func disableSFTPAccount(ctx context.Context, siteID string) error {
	return disableSFTPAccountWith(ctx, siteID, defaultSSHDEnvironment())
}

func disableSFTPAccountWith(ctx context.Context, siteID string, env sshdEnvironment) error {
	if !validSiteID(siteID) {
		return errors.New("sftp.disable_account payload is invalid")
	}
	sshdMu.Lock()
	defer sshdMu.Unlock()
	root, err := os.OpenRoot(env.root)
	if err != nil {
		return err
	}
	defer root.Close()
	name := "tompanel-" + siteID + ".conf"
	old, err := root.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(old), "# Managed by TomPanel: "+siteID+"\n") {
		return errors.New("refusing to disable an unmanaged sshd config")
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	if err := env.run(ctx, sshdBinary, "-t"); err != nil {
		_ = root.WriteFile(name, old, 0o644)
		return err
	}
	if err := env.run(ctx, "/usr/bin/systemctl", "reload", "ssh"); err != nil {
		_ = root.WriteFile(name, old, 0o644)
		_ = env.run(ctx, "/usr/bin/systemctl", "reload", "ssh")
		return err
	}
	return nil
}

func validateSFTPPassword(password string) error {
	if len(password) < 16 || len(password) > 128 {
		return errors.New("sftp password length must be between 16 and 128 characters")
	}
	for _, r := range password {
		if r <= 0x20 || r == 0x7f || r == ':' {
			return errors.New("sftp password contains unsupported characters")
		}
	}
	return nil
}

func runCommandInput(ctx context.Context, name string, stdin []byte, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(stdin)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func rotateSFTPPassword(ctx context.Context, input sftpPasswordInput) error {
	return rotateSFTPPasswordWith(ctx, input, runCommandInput)
}

func rotateSFTPPasswordWith(ctx context.Context, input sftpPasswordInput, runInput func(context.Context, string, []byte, ...string) error) error {
	if !validSiteID(input.SiteID) {
		return errors.New("sftp.rotate_password payload is invalid")
	}
	if err := validateSFTPPassword(input.Password); err != nil {
		return err
	}
	username := "tp_" + input.SiteID[:16]
	payload := []byte(username + ":" + input.Password + "\n")
	return runInput(ctx, chpasswdBinary, payload)
}

type parsedSSHKey struct {
	keyType     string
	blob        []byte
	comment     string
	fingerprint string
}

// parsePublicKeyLine accepts one authorized_keys line and derives its
// fingerprint. Only allowlisted key types with canonical wire encoding pass.
func parsePublicKeyLine(line string) (parsedSSHKey, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || len(line) > 8192 || strings.ContainsAny(line, "\n\r\x00") {
		return parsedSSHKey{}, errors.New("public key line is malformed")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 || len(fields) > 3 {
		return parsedSSHKey{}, errors.New("public key line is malformed")
	}
	keyType := fields[0]
	if !allowedSSHKeyTypes[keyType] {
		return parsedSSHKey{}, errors.New("public key type is not allowed")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) == 0 {
		return parsedSSHKey{}, errors.New("public key body is malformed")
	}
	if base64.StdEncoding.EncodeToString(blob) != fields[1] {
		return parsedSSHKey{}, errors.New("public key body is not canonical")
	}
	if len(blob) < 4 || int(blob[0])<<24|int(blob[1])<<16|int(blob[2])<<8|int(blob[3]) != len(keyType) || string(blob[4:4+len(keyType)]) != keyType {
		return parsedSSHKey{}, errors.New("public key body does not match its type")
	}
	comment := ""
	if len(fields) == 3 {
		comment = fields[2]
		if len(comment) > 1024 || strings.ContainsAny(comment, "\x00") {
			return parsedSSHKey{}, errors.New("public key comment is malformed")
		}
	}
	sum := sha256.Sum256(blob)
	return parsedSSHKey{
		keyType: keyType, blob: blob, comment: comment,
		fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
	}, nil
}

func addSFTPKey(ctx context.Context, input sftpKeyInput) (sftpKeyResult, error) {
	return addSFTPKeyWith(ctx, input, siteRootPath)
}

func addSFTPKeyWith(ctx context.Context, input sftpKeyInput, sitesRoot string) (sftpKeyResult, error) {
	if !validSiteID(input.SiteID) {
		return sftpKeyResult{}, errors.New("sftp.add_key payload is invalid")
	}
	parsed, err := parsePublicKeyLine(input.PublicKey)
	if err != nil {
		return sftpKeyResult{}, err
	}
	root, err := os.OpenRoot(sitesRoot)
	if err != nil {
		return sftpKeyResult{}, err
	}
	defer root.Close()
	sshDir := filepath.Join(input.SiteID, ".ssh")
	if err := root.MkdirAll(sshDir, 0o755); err != nil {
		return sftpKeyResult{}, fmt.Errorf("create ssh directory: %w", err)
	}
	keyPath := filepath.Join(sshDir, "authorized_keys")
	existing, err := root.ReadFile(keyPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return sftpKeyResult{}, err
	}
	var kept []string
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		stored, err := parsePublicKeyLine(line)
		if err != nil {
			return sftpKeyResult{}, errors.New("stored authorized_keys entry is malformed")
		}
		if stored.fingerprint == parsed.fingerprint {
			return sftpKeyResult{}, errors.New("public key is already authorized")
		}
		kept = append(kept, line)
	}
	content := strings.Join(append(kept, strings.TrimSpace(input.PublicKey)), "\n") + "\n"
	if err := writeTempInRoot(root, keyPath, []byte(content), 0o600); err != nil {
		return sftpKeyResult{}, err
	}
	return sftpKeyResult{Fingerprint: parsed.fingerprint}, nil
}

func removeSFTPKey(ctx context.Context, input sftpKeyInput) error {
	return removeSFTPKeyWith(ctx, input, siteRootPath)
}

func removeSFTPKeyWith(ctx context.Context, input sftpKeyInput, sitesRoot string) error {
	if !validSiteID(input.SiteID) || input.Fingerprint == "" || len(input.Fingerprint) > 128 || strings.ContainsAny(input.Fingerprint, " \t\n\r") {
		return errors.New("sftp.remove_key payload is invalid")
	}
	root, err := os.OpenRoot(sitesRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	keyPath := filepath.Join(input.SiteID, ".ssh", "authorized_keys")
	existing, err := root.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("authorized_keys entry not found")
	}
	if err != nil {
		return err
	}
	var kept []string
	removed := false
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		stored, err := parsePublicKeyLine(line)
		if err != nil {
			return errors.New("stored authorized_keys entry is malformed")
		}
		if stored.fingerprint == input.Fingerprint {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return errors.New("authorized_keys entry not found")
	}
	if len(kept) == 0 {
		if err := root.Remove(keyPath); err != nil {
			return err
		}
		_ = root.Remove(filepath.Join(input.SiteID, ".ssh"))
		return nil
	}
	content := strings.Join(kept, "\n") + "\n"
	if err := writeTempInRoot(root, keyPath, []byte(content), 0o600); err != nil {
		return err
	}
	return nil
}

// writeTempInRoot replaces target atomically with content at the given mode.
func writeTempInRoot(root *os.Root, target string, content []byte, mode os.FileMode) error {
	temporary, err := tempNameFor()
	if err != nil {
		return err
	}
	if err := root.WriteFile(temporary, content, mode); err != nil {
		return err
	}
	if err := root.Rename(temporary, target); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	return nil
}

func tempNameFor() (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate temporary name: %w", err)
	}
	return ".tompanel-candidate-" + hex.EncodeToString(value[:]), nil
}
