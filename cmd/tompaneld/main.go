package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/web"
	"golang.org/x/sys/unix"
)

const daemonLockName = "tompaneld.lock"

var errDaemonAlreadyRunning = errors.New("tompaneld is already running for this state directory")

type daemonStartup struct {
	listener net.Listener
	lock     *os.File
}

func acquireDaemonStartup(cfg config.Config) (*daemonStartup, error) {
	lock, err := os.OpenFile(filepath.Join(cfg.StateDir, daemonLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errDaemonAlreadyRunning
		}
		return nil, fmt.Errorf("lock daemon instance: %w", err)
	}
	if err := lock.Chmod(0o600); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("secure daemon lock: %w", err)
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	return &daemonStartup{listener: listener, lock: lock}, nil
}

func (s *daemonStartup) Close() {
	_ = s.listener.Close()
	_ = s.lock.Close()
}

func main() {
	configPath := flag.String("config", "/etc/tompanel/config.toml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config.Config) error {
	startup, err := acquireDaemonStartup(cfg)
	if err != nil {
		return err
	}
	defer startup.Close()

	app, err := web.New(cfg)
	if err != nil {
		return err
	}
	defer app.Close()

	log.Printf("tompaneld listening on %s", startup.listener.Addr())
	return http.Serve(startup.listener, app.Handler())
}
