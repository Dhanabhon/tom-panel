package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// agentManagedUnits mirrors the panel allowlist: the agent refuses any unit
// outside this set regardless of what the panel sends.
var agentManagedUnits = map[string]bool{
	"nginx.service":        true,
	"mariadb.service":      true,
	"php8.3-fpm.service":   true,
	"php8.4-fpm.service":   true,
	"php8.5-fpm.service":   true,
	"redis-server.service": true,
}

type serviceUnitInput struct {
	Unit string `json:"unit"`
}

type serviceInspectResult struct {
	Active bool   `json:"active"`
	State  string `json:"state"`
}

type serviceRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func validateManagedUnit(unit string) error {
	if !agentManagedUnits[unit] {
		return errors.New("service unit is not managed by tompanel")
	}
	if strings.ContainsAny(unit, " \t\n\r;/|&$`") {
		return errors.New("service unit is malformed")
	}
	return nil
}

func inspectService(ctx context.Context, input serviceUnitInput, run serviceRunner) (serviceInspectResult, error) {
	if err := validateManagedUnit(input.Unit); err != nil {
		return serviceInspectResult{}, err
	}
	output, err := run(ctx, "/usr/bin/systemctl", "show", input.Unit, "--property=ActiveState,SubState", "--no-pager")
	if err != nil {
		return serviceInspectResult{}, fmt.Errorf("inspect %s: %s: %w", input.Unit, strings.TrimSpace(string(output)), err)
	}
	result := serviceInspectResult{State: "unknown"}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "ActiveState":
			result.Active = value == "active"
			result.State = value
		case "SubState":
			if result.State != "unknown" && value != "" {
				result.State = result.State + "/" + value
			}
		}
	}
	return result, nil
}

func serviceAction(ctx context.Context, input serviceUnitInput, action string, run serviceRunner) error {
	if err := validateManagedUnit(input.Unit); err != nil {
		return err
	}
	output, err := run(ctx, "/usr/bin/systemctl", action, input.Unit, "--no-pager")
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", action, input.Unit, strings.TrimSpace(string(output)), err)
	}
	return nil
}

const nginxAccessLog = "/var/log/nginx/access.log"
const nginxErrorLog = "/var/log/nginx/error.log"
const logReadMaxBytes = 4 << 20
const logReadMaxLines = 400

type logReadInput struct {
	SiteID   string `json:"site_id"`
	Source   string `json:"source"`
	Domain   string `json:"domain"`
	Search   string `json:"search"`
	MaxLines int    `json:"max_lines"`
}

type logReadResult struct {
	Lines []string `json:"lines"`
}

// readLog tails TomPanel-owned log locations with hard byte and line bounds.
// The nginx source filters shared logs down to the requesting site's domain.
func readLog(_ context.Context, input logReadInput) (logReadResult, error) {
	if !validSiteID(input.SiteID) {
		return logReadResult{}, errors.New("log.read payload is invalid")
	}
	if input.MaxLines <= 0 || input.MaxLines > logReadMaxLines {
		input.MaxLines = logReadMaxLines
	}
	if len(input.Search) > 256 || strings.ContainsAny(input.Search, "\n\r") {
		return logReadResult{}, errors.New("log.read search is invalid")
	}
	var paths []string
	var filter string
	switch input.Source {
	case "nginx":
		paths = []string{nginxAccessLog, nginxErrorLog}
		filter = input.Domain
	case "app":
		paths = []string{siteRootPath + "/" + input.SiteID + "/storage/logs/laravel.log"}
	default:
		return logReadResult{}, errors.New("log.read source is unsupported")
	}
	if input.Source == "nginx" && filter == "" {
		return logReadResult{}, errors.New("log.read requires the site domain for nginx sources")
	}
	var lines []string
	for _, path := range paths {
		content, err := tailBytes(path, logReadMaxBytes)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return logReadResult{}, err
		}
		for _, line := range splitLines(content) {
			if filter != "" && !bytes.Contains(line, []byte(filter)) {
				continue
			}
			if input.Search != "" && !bytes.Contains(bytes.ToLower(line), []byte(strings.ToLower(input.Search))) {
				continue
			}
			lines = append(lines, string(line))
			if len(lines) >= input.MaxLines {
				return logReadResult{Lines: lines}, nil
			}
		}
	}
	return logReadResult{Lines: lines}, nil
}

func tailBytes(path string, limit int64) ([]byte, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	var offset int64
	if info.Size() > limit {
		offset = info.Size() - limit
	}
	if _, err := handle.Seek(offset, 0); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(handle, limit))
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		// Drop the partial first line from a mid-file start.
		if index := bytes.IndexByte(content, '\n'); index >= 0 {
			content = content[index+1:]
		}
	}
	return content, nil
}

func splitLines(content []byte) [][]byte {
	clean := bytes.TrimSuffix(content, []byte("\n"))
	if len(clean) == 0 {
		return nil
	}
	raw := bytes.Split(clean, []byte("\n"))
	// Newest lines last in the file; keep the newest for display.
	if len(raw) > logReadMaxLines*2 {
		raw = raw[len(raw)-logReadMaxLines*2:]
	}
	return raw
}
