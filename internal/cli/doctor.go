// Doctor: the read-only health report of the tomlpanel CLI. It never mutates
// configuration; opening the store applies pending migrations exactly as the
// daemon would at start, which is the honest way to verify database health.
package cli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

// DoctorCheck is one line of the health report.
type DoctorCheck struct {
	Name   string
	Passed bool
	Detail string
	Hint   string
}

// Doctor runs the read-only diagnostics. Collaborators are fields so tests
// can inject failures without root, systemd, or an agent socket.
type Doctor struct {
	Config       config.Config
	KeyPath      string
	AgentCall    func(ctx context.Context, operation string, input, output any) error
	NginxBinary  string
	SitesEnabled string
	UFWBinary    string
	SystemdRun   string
}

// MasterKeyPath resolves the master key location for a configuration. The
// packaged deployment keeps the key under /etc even when state is elsewhere.
func MasterKeyPath(cfg config.Config) string {
	if filepath.Clean(cfg.StateDir) == "/var/lib/tompanel" {
		return "/etc/tompanel/master.key"
	}
	return filepath.Join(cfg.StateDir, "master.key")
}

// NewDoctor builds a Doctor with production defaults.
func NewDoctor(cfg config.Config) *Doctor {
	return &Doctor{
		Config:       cfg,
		KeyPath:      MasterKeyPath(cfg),
		NginxBinary:  "/usr/sbin/nginx",
		SitesEnabled: "/etc/nginx/sites-enabled",
		UFWBinary:    "/usr/sbin/ufw",
		SystemdRun:   "/run/systemd/system",
	}
}

// Run executes every check, prints one line each, and returns how many
// failed so callers can set the exit status.
func (d *Doctor) Run(ctx context.Context, w io.Writer) int {
	failed := 0
	report := func(check DoctorCheck) {
		if !check.Passed {
			failed++
		}
		status := "PASS"
		if !check.Passed {
			status = "FAIL"
		}
		line := fmt.Sprintf("[%s] %s", status, check.Name)
		if check.Detail != "" {
			line += " — " + check.Detail
		}
		fmt.Fprintln(w, line)
		if check.Hint != "" {
			fmt.Fprintf(w, "       hint: %s\n", check.Hint)
		}
	}

	report(d.checkMasterKey())
	report(d.checkStateDirectory())
	report(d.checkDiskSpace())
	report(d.checkDatabase(ctx))
	report(d.checkAgent(ctx))
	report(d.checkNginx())
	report(d.checkUFW())
	report(d.checkSystemd())
	return failed
}

func (d *Doctor) checkMasterKey() DoctorCheck {
	info, err := os.Stat(d.KeyPath)
	if err != nil {
		return DoctorCheck{Name: "master key", Detail: d.KeyPath + ": " + err.Error(),
			Hint: "the key is created by the package postinst; never move it manually"}
	}
	handle, err := os.Open(d.KeyPath)
	if err != nil {
		return DoctorCheck{Name: "master key", Detail: "not readable: " + err.Error(),
			Hint: "chown tompanel:tompanel " + d.KeyPath + " && chmod 0400 " + d.KeyPath}
	}
	handle.Close()
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return DoctorCheck{Name: "master key", Passed: true,
			Detail: fmt.Sprintf("readable but permissions are %o (want 0400)", mode),
			Hint:   "chmod 0400 " + d.KeyPath}
	}
	return DoctorCheck{Name: "master key", Passed: true, Detail: "mode 0400"}
}

func (d *Doctor) checkStateDirectory() DoctorCheck {
	handle, err := os.CreateTemp(d.Config.StateDir, ".doctor-*")
	if err != nil {
		return DoctorCheck{Name: "state directory", Detail: "not writable: " + err.Error(),
			Hint: "chown tompanel:tompanel " + d.Config.StateDir}
	}
	name := handle.Name()
	handle.Close()
	os.Remove(name)
	return DoctorCheck{Name: "state directory", Passed: true, Detail: d.Config.StateDir + " is writable"}
}

func (d *Doctor) checkDiskSpace() DoctorCheck {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(d.Config.StateDir, &stat); err != nil {
		return DoctorCheck{Name: "disk space", Detail: "statfs failed: " + err.Error()}
	}
	if stat.Bsize <= 0 {
		return DoctorCheck{Name: "disk space", Detail: "block size unavailable"}
	}
	free := stat.Bavail * uint64(stat.Bsize)
	gigabytes := strconv.FormatUint(free>>30, 10)
	if free < 1<<30 {
		return DoctorCheck{Name: "disk space", Detail: gigabytes + " GiB free",
			Hint: "backups stop below the safety threshold; free space on the state volume"}
	}
	return DoctorCheck{Name: "disk space", Passed: true, Detail: gigabytes + " GiB free"}
}

func (d *Doctor) checkDatabase(ctx context.Context) DoctorCheck {
	database, err := store.Open(ctx, filepath.Join(d.Config.StateDir, "tompanel.db"), d.KeyPath)
	if err != nil {
		return DoctorCheck{Name: "database", Detail: err.Error(),
			Hint: "state files must be readable by the service account"}
	}
	var applied int
	if err := database.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&applied)
	}); err != nil {
		return DoctorCheck{Name: "database", Detail: "migration ledger unreadable: " + err.Error()}
	}
	return DoctorCheck{Name: "database", Passed: true,
		Detail: fmt.Sprintf("open, %d migration(s) applied", applied)}
}

func (d *Doctor) checkAgent(ctx context.Context) DoctorCheck {
	call := d.AgentCall
	if call == nil {
		client := agentapi.NewClient(d.Config.AgentSocket)
		call = client.Call
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := call(pingCtx, "system.inspect", struct{}{}, &struct{}{}); err != nil {
		return DoctorCheck{Name: "privileged agent", Detail: err.Error(),
			Hint: "is tompanel-agent.service active? check the socket path in the config"}
	}
	return DoctorCheck{Name: "privileged agent", Passed: true,
		Detail: d.Config.AgentSocket + " answered a typed ping"}
}

func (d *Doctor) checkNginx() DoctorCheck {
	if _, err := os.Stat(d.NginxBinary); err != nil {
		return DoctorCheck{Name: "nginx", Detail: d.NginxBinary + " not found"}
	}
	enabled := d.SitesEnabled
	if _, err := os.Stat(enabled); err != nil {
		return DoctorCheck{Name: "nginx", Detail: enabled + ": " + err.Error(),
			Hint: "the packaged nginx layout is expected"}
	}
	return DoctorCheck{Name: "nginx", Passed: true, Detail: "binary and site root present"}
}

func (d *Doctor) checkUFW() DoctorCheck {
	if _, err := os.Stat(d.UFWBinary); err != nil {
		return DoctorCheck{Name: "firewall (ufw)", Detail: d.UFWBinary + " not found",
			Hint: "the installer enables UFW; install it with apt if it was removed"}
	}
	return DoctorCheck{Name: "firewall (ufw)", Passed: true}
}

func (d *Doctor) checkSystemd() DoctorCheck {
	if _, err := os.Stat(d.SystemdRun); err != nil {
		return DoctorCheck{Name: "systemd", Detail: "not running (" + d.SystemdRun + " missing)",
			Hint: "services are managed by systemd on the supported platform"}
	}
	return DoctorCheck{Name: "systemd", Passed: true, Detail: "running"}
}

// RunDoctor prints the report and returns an error when any check failed so
// the CLI exits non-zero.
func RunDoctor(ctx context.Context, cfg config.Config, w io.Writer) error {
	doctor := NewDoctor(cfg)
	failed := doctor.Run(ctx, w)
	if failed > 0 {
		return fmt.Errorf("doctor found %d failing check(s)", failed)
	}
	return nil
}
