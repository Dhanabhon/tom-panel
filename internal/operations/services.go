package operations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

var ErrUnmanagedService = errors.New("service is not managed by tompanel")

// ManagedKeys maps stable product keys to their fixed systemd units. Only
// these units accept lifecycle actions.
var ManagedKeys = map[string]string{
	"nginx":   "nginx.service",
	"mariadb": "mariadb.service",
	"php8.3":  "php8.3-fpm.service",
	"php8.4":  "php8.4-fpm.service",
	"php8.5":  "php8.5-fpm.service",
	"redis":   "redis-server.service",
}

// ManagedService is one allowlisted unit with its impact report.
type ManagedService struct {
	Key           string   `json:"key"`
	Unit          string   `json:"unit"`
	Active        bool     `json:"active"`
	State         string   `json:"state"`
	ImpactedSites []string `json:"impacted_sites"`
}

// ServiceManager inspects and controls only TomPanel-owned units.
type ServiceManager struct {
	agent func(ctx context.Context, operation string, input, output any) error
	sites func(ctx context.Context) ([]siteSummary, error)
}

type siteSummary struct {
	ID          string
	Kind        string
	PHPVersion  string
	HasDatabase bool
	UsesRedis   bool
	Domain      string
}

// NewServiceManager builds the manager over the panel database and agent.
func NewServiceManager(database interface {
	Tx(ctx context.Context, fn func(tx *sql.Tx) error) error
}, agentCall func(ctx context.Context, operation string, input, output any) error) *ServiceManager {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &ServiceManager{
		agent: call,
		sites: func(ctx context.Context) ([]siteSummary, error) {
			var summaries []siteSummary
			err := database.Tx(ctx, func(tx *sql.Tx) error {
				rows, err := tx.QueryContext(ctx, `SELECT s.id, s.kind, coalesce(s.php_version, ''), s.primary_domain,
					EXISTS (SELECT 1 FROM databases d WHERE d.site_id = s.id),
					EXISTS (SELECT 1 FROM app_installations a WHERE a.site_id = s.id AND a.redis_cache = 1)
					FROM sites s WHERE s.state IN ('active', 'disabled', 'provisioning', 'deleting')`)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var summary siteSummary
					if err := rows.Scan(&summary.ID, &summary.Kind, &summary.PHPVersion, &summary.Domain, &summary.HasDatabase, &summary.UsesRedis); err != nil {
						return err
					}
					summaries = append(summaries, summary)
				}
				return rows.Err()
			})
			return summaries, err
		},
	}
}

// Inspect reports every allowlisted unit and which sites it serves.
func (m *ServiceManager) Inspect(ctx context.Context) ([]ManagedService, error) {
	summaries, err := m.sites(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(ManagedKeys))
	for key := range ManagedKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ManagedService, 0, len(keys))
	for _, key := range keys {
		unit := ManagedKeys[key]
		service := ManagedService{Key: key, Unit: unit, ImpactedSites: m.impactedSites(key, summaries)}
		var state struct {
			Active bool   `json:"active"`
			State  string `json:"state"`
		}
		if err := m.agent(ctx, "service.inspect", struct {
			Unit string `json:"unit"`
		}{unit}, &state); err == nil {
			service.Active, service.State = state.Active, state.State
		} else {
			service.State = "unknown"
		}
		result = append(result, service)
	}
	return result, nil
}

func (m *ServiceManager) impactedSites(key string, summaries []siteSummary) []string {
	var impacted []string
	for _, summary := range summaries {
		affected := false
		switch key {
		case "nginx":
			affected = true
		case "mariadb":
			affected = summary.HasDatabase
		case "php8.3", "php8.4", "php8.5":
			affected = summary.Kind == "php" && summary.PHPVersion == key[3:]
		case "redis":
			affected = summary.UsesRedis
		}
		if affected {
			impacted = append(impacted, summary.Domain)
		}
	}
	return impacted
}

// Restart restarts one allowlisted unit.
func (m *ServiceManager) Restart(ctx context.Context, key string) error {
	return m.action(ctx, key, "service.restart")
}

// Start starts one allowlisted unit.
func (m *ServiceManager) Start(ctx context.Context, key string) error {
	return m.action(ctx, key, "service.start")
}

// Stop stops one allowlisted unit.
func (m *ServiceManager) Stop(ctx context.Context, key string) error {
	return m.action(ctx, key, "service.stop")
}

func (m *ServiceManager) action(ctx context.Context, key, operation string) error {
	unit, ok := ManagedKeys[key]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnmanagedService, key)
	}
	return m.agent(ctx, operation, struct {
		Unit string `json:"unit"`
	}{unit}, &struct{}{})
}
