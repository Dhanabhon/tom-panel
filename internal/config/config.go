package config

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Config contains the non-secret settings needed to start TomPanel.
type Config struct {
	Listen      string
	StateDir    string
	AgentSocket string
}

// Load reads the small TOML subset used by TomPanel's bootstrap configuration.
func Load(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	seen := make(map[string]bool)
	for lineNumber, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("config line %d: expected key = value", lineNumber+1)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return Config{}, fmt.Errorf("config line %d: value for %q must be quoted", lineNumber+1, key)
		}
		if seen[key] {
			return Config{}, fmt.Errorf("config line %d: duplicate key %q", lineNumber+1, key)
		}
		seen[key] = true

		switch key {
		case "listen":
			cfg.Listen = value[1 : len(value)-1]
		case "state_dir":
			cfg.StateDir = value[1 : len(value)-1]
		case "agent_socket":
			cfg.AgentSocket = value[1 : len(value)-1]
		default:
			return Config{}, fmt.Errorf("config line %d: unknown key %q", lineNumber+1, key)
		}
	}

	if cfg.Listen == "" || cfg.StateDir == "" || cfg.AgentSocket == "" {
		return Config{}, fmt.Errorf("config requires listen, state_dir, and agent_socket")
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return Config{}, fmt.Errorf("invalid listen address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return Config{}, fmt.Errorf("listen address must use a loopback IP")
	}

	return cfg, nil
}
