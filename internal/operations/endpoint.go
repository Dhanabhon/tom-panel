package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/jobs"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

var (
	ErrCloudflarePort   = errors.New("cloudflare proxy requires port 443 or 8443")
	ErrEndpointHostname = errors.New("endpoint hostname conflicts with a managed site")
	ErrEndpointInvalid  = errors.New("endpoint configuration is invalid")
	// EndpointChangeJobKind re-routes the panel with zero downtime.
	EndpointChangeJobKind = "endpoint.change"
)

// EndpointConfig is one validated panel exposure configuration.
type EndpointConfig struct {
	Mode            string `json:"mode"` // loopback | public
	Hostname        string `json:"hostname,omitempty"`
	Port            uint16 `json:"port,omitempty"`
	CloudflareProxy bool   `json:"cloudflare_proxy,omitempty"`
	AcmeEmail       string `json:"acme_email,omitempty"`
}

var endpointHostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ValidateEndpoint applies the endpoint rules: the hostname may not collide
// with any managed site, and Cloudflare-proxied ports are limited to the
// official HTTPS ports.
func ValidateEndpoint(config EndpointConfig, reservedHostnames []string) error {
	switch config.Mode {
	case "loopback":
		if config.Hostname != "" || config.Port != 0 || config.CloudflareProxy {
			return fmt.Errorf("%w: loopback takes no hostname or port", ErrEndpointInvalid)
		}
		return nil
	case "public":
	default:
		return fmt.Errorf("%w: mode", ErrEndpointInvalid)
	}
	hostname := strings.ToLower(strings.TrimSuffix(config.Hostname, "."))
	if !endpointHostnamePattern.MatchString(hostname) || len(hostname) > 253 {
		return fmt.Errorf("%w: hostname", ErrEndpointInvalid)
	}
	for _, reserved := range reservedHostnames {
		if strings.EqualFold(reserved, hostname) {
			return fmt.Errorf("%w: %s", ErrEndpointHostname, hostname)
		}
	}
	if config.CloudflareProxy && config.Port != 443 && config.Port != 8443 {
		return fmt.Errorf("%w: %d", ErrCloudflarePort, config.Port)
	}
	if config.Port == 0 || config.Port == 80 {
		return fmt.Errorf("%w: public endpoints are HTTPS only", ErrEndpointInvalid)
	}
	if email := strings.TrimSpace(config.AcmeEmail); email == "" || len(email) > 254 || !strings.Contains(email, "@") {
		return fmt.Errorf("%w: acme email", ErrEndpointInvalid)
	}
	return nil
}

type endpointJobInput struct {
	Config EndpointConfig `json:"config"`
}

// EndpointChanger applies validated endpoint configurations atomically: the
// new route is health-checked before the old one is removed.
type EndpointChanger struct {
	store   *store.Store
	agent   func(ctx context.Context, operation string, input, output any) error
	issue   func(ctx context.Context, config EndpointConfig) error
	health  func(ctx context.Context, hostname string, port uint16) error
	now     func() time.Time
	current func(ctx context.Context) (EndpointConfig, error)
}

// NewEndpointChanger builds the changer over persisted endpoint state.
func NewEndpointChanger(database *store.Store, agentCall func(ctx context.Context, operation string, input, output any) error) *EndpointChanger {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &EndpointChanger{
		store: database, agent: call, now: time.Now,
		issue: func(context.Context, EndpointConfig) error { return nil },
		health: func(ctx context.Context, hostname string, port uint16) error {
			dialer := net.Dialer{Timeout: 10 * time.Second}
			connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, fmt.Sprint(port)))
			if err != nil {
				return fmt.Errorf("new endpoint unreachable: %w", err)
			}
			return connection.Close()
		},
		current: func(ctx context.Context) (EndpointConfig, error) {
			var raw string
			err := database.Tx(ctx, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'panel.endpoint'").Scan(&raw)
			})
			if errors.Is(err, sql.ErrNoRows) {
				return EndpointConfig{Mode: "loopback"}, nil
			}
			if err != nil {
				return EndpointConfig{}, err
			}
			var config EndpointConfig
			if err := json.Unmarshal([]byte(raw), &config); err != nil {
				return EndpointConfig{}, fmt.Errorf("%w: stored endpoint", ErrEndpointInvalid)
			}
			return config, nil
		},
	}
}

// SetCertificateIssuer installs the certificate provisioning hook.
func (c *EndpointChanger) SetCertificateIssuer(issue func(ctx context.Context, config EndpointConfig) error) {
	if issue != nil {
		c.issue = issue
	}
}

// Current returns the active endpoint configuration.
func (c *EndpointChanger) Current(ctx context.Context) (EndpointConfig, error) {
	return c.current(ctx)
}

// ReservedHostnames lists hostnames the endpoint may not take over.
func ReservedHostnames(ctx context.Context, database *store.Store) ([]string, error) {
	var hostnames []string
	err := database.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT hostname FROM domains")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var hostname string
			if err := rows.Scan(&hostname); err != nil {
				return err
			}
			hostnames = append(hostnames, hostname)
		}
		return rows.Err()
	})
	return hostnames, err
}

// BuildEndpointChangeJob assembles the zero-downtime endpoint switch.
func (c *EndpointChanger) BuildEndpointChangeJob(ctx context.Context, config EndpointConfig) (jobs.Definition, error) {
	reserved, err := ReservedHostnames(ctx, c.store)
	if err != nil {
		return jobs.Definition{}, err
	}
	if err := ValidateEndpoint(config, reserved); err != nil {
		return jobs.Definition{}, err
	}
	input, err := json.Marshal(endpointJobInput{Config: config})
	if err != nil {
		return jobs.Definition{}, err
	}
	previous, err := c.current(ctx)
	if err != nil {
		return jobs.Definition{}, err
	}
	return c.build(input, config, previous), nil
}

func (c *EndpointChanger) build(input json.RawMessage, config, previous EndpointConfig) jobs.Definition {
	return jobs.Definition{
		Kind:  EndpointChangeJobKind,
		Input: input,
		Steps: []jobs.Step{
			{Key: "certificate", Run: func(ctx context.Context) (json.RawMessage, error) {
				if config.Mode != "public" {
					return nil, nil
				}
				return nil, c.issue(ctx, config)
			}},
			{Key: "activate", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, c.agent(ctx, "endpoint.activate", struct {
					Config EndpointConfig `json:"config"`
				}{config}, &struct{}{})
			}},
			{Key: "health", Run: func(ctx context.Context) (json.RawMessage, error) {
				if config.Mode != "public" {
					return nil, nil
				}
				return nil, c.health(ctx, config.Hostname, config.Port)
			}},
			{Key: "commit", Run: func(ctx context.Context) (json.RawMessage, error) {
				return nil, c.commit(ctx, config)
			}},
		},
	}
}

// Rollback restores the previous route when the new one never got healthy.
func (c *EndpointChanger) Rollback(ctx context.Context, previous EndpointConfig) error {
	if err := c.agent(ctx, "endpoint.activate", struct {
		Config EndpointConfig `json:"config"`
	}{previous}, &struct{}{}); err != nil {
		return err
	}
	return c.commit(ctx, previous)
}

func (c *EndpointChanger) commit(ctx context.Context, config EndpointConfig) error {
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	now := c.now().UTC().Unix()
	return c.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at) VALUES ('panel.endpoint', ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, string(encoded), now)
		return err
	})
}

// Register wires the endpoint job builder into the manager.
func (c *EndpointChanger) Register(manager *jobs.Manager) error {
	return manager.Register(EndpointChangeJobKind, func(input json.RawMessage) (jobs.Definition, error) {
		var parsed endpointJobInput
		if err := json.Unmarshal(input, &parsed); err != nil {
			return jobs.Definition{}, err
		}
		previous, err := c.current(context.Background())
		if err != nil {
			return jobs.Definition{}, err
		}
		return c.build(input, parsed.Config, previous), nil
	})
}
