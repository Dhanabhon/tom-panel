// Package integrations stores optional provider connections with encrypted
// secrets and bounded alert delivery.
package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/backups"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

var (
	ErrProviderUnsupported = errors.New("integration provider is unsupported")
	ErrNotConfigured       = errors.New("integration is not configured")
	ErrInvalidSettings     = errors.New("integration settings are invalid")
)

const (
	ProviderS3   = "s3"
	ProviderSMTP = "smtp"
)

// SMTPSettings describes the outbound mail relay.
type SMTPSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	From     string `json:"from"`
	Password string `json:"-"`
}

// Valid enforces a submission-safe SMTP configuration.
func (s SMTPSettings) Valid() bool {
	if s.Host == "" || len(s.Host) > 253 || strings.ContainsAny(s.Host, " \t\n\r") {
		return false
	}
	if s.Port < 1 || s.Port > 65535 {
		return false
	}
	if s.From == "" || len(s.From) > 254 || !strings.Contains(s.From, "@") {
		return false
	}
	return true
}

// Alert is one bounded notification.
type Alert struct {
	Kind    string `json:"kind"` // job_failed | security | recovery
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// CloudflareSaver mirrors the domains service configuration entry point.
type CloudflareSaver interface {
	ConfigureCloudflare(ctx context.Context, zoneID, token string) error
}

// Service owns provider settings. Secrets are encrypted with provider
// specific associated data and never rendered back.
type Service struct {
	store         *store.Store
	now           func() time.Time
	cloudflare    CloudflareSaver
	agent         func(ctx context.Context, operation string, input, output any) error
	smtpDial      func(ctx context.Context, settings SMTPSettings) error
	cloudflareTry func(ctx context.Context, zoneID, token string) error
}

// NewService builds the integrations service.
func NewService(database *store.Store, cloudflare CloudflareSaver, agentCall func(ctx context.Context, operation string, input, output any) error) *Service {
	call := agentCall
	if call == nil {
		call = func(context.Context, string, any, any) error { return errors.New("privileged agent is unavailable") }
	}
	return &Service{
		store: database, now: time.Now, cloudflare: cloudflare, agent: call,
		smtpDial:      func(ctx context.Context, settings SMTPSettings) error { return smtpHandshake(ctx, settings) },
		cloudflareTry: func(ctx context.Context, zoneID, token string) error { return cloudflareVerifyZone(ctx, zoneID, token) },
	}
}

// SaveCloudflare stores the DNS integration through the domains service.
func (s *Service) SaveCloudflare(ctx context.Context, zoneID, token string) error {
	if s.cloudflare == nil {
		return errors.New("cloudflare integration is unavailable")
	}
	if len(zoneID) < 16 || len(zoneID) > 64 || strings.ContainsAny(zoneID, " \t\n\r") {
		return fmt.Errorf("%w: zone id", ErrInvalidSettings)
	}
	if len(token) < 20 || len(token) > 512 || strings.ContainsAny(token, " \t\n\r") {
		return fmt.Errorf("%w: token", ErrInvalidSettings)
	}
	return s.cloudflare.ConfigureCloudflare(ctx, zoneID, token)
}

// SaveS3 validates and stores object storage settings.
func (s *Service) SaveS3(ctx context.Context, settings backups.RemoteSettings) error {
	if !settings.Valid() {
		return fmt.Errorf("%w: s3", ErrInvalidSettings)
	}
	if _, err := url.Parse(settings.Endpoint); settings.Endpoint != "" && err != nil {
		return fmt.Errorf("%w: endpoint", ErrInvalidSettings)
	}
	return s.save(ctx, ProviderS3, map[string]string{
		"endpoint": settings.Endpoint, "region": settings.Region, "bucket": settings.Bucket,
		"prefix": settings.Prefix, "age_recipient": settings.AgeRecipient,
	}, map[string]string{"access_key": settings.AccessKeyID, "secret_key": settings.SecretKey})
}

// S3 returns the stored settings with decrypted credentials.
func (s *Service) S3(ctx context.Context) (backups.RemoteSettings, bool, error) {
	var settings backups.RemoteSettings
	config, secrets, err := s.load(ctx, ProviderS3)
	if errors.Is(err, ErrNotConfigured) {
		return backups.RemoteSettings{}, false, nil
	}
	if err != nil {
		return backups.RemoteSettings{}, false, err
	}
	if value, ok := config["endpoint"]; ok {
		settings.Endpoint = value
	}
	settings.Region, settings.Bucket, settings.Prefix, settings.AgeRecipient = config["region"], config["bucket"], config["prefix"], config["age_recipient"]
	settings.AccessKeyID, settings.SecretKey = secrets["access_key"], secrets["secret_key"]
	return settings, settings.Valid(), nil
}

// SaveSMTP validates and stores the relay settings.
func (s *Service) SaveSMTP(ctx context.Context, settings SMTPSettings) error {
	if !settings.Valid() {
		return fmt.Errorf("%w: smtp", ErrInvalidSettings)
	}
	if settings.Password == "" || len(settings.Password) > 256 || strings.ContainsAny(settings.Password, "\n\r") {
		return fmt.Errorf("%w: smtp password", ErrInvalidSettings)
	}
	return s.save(ctx, ProviderSMTP, map[string]string{
		"host": settings.Host, "port": fmt.Sprint(settings.Port), "username": settings.Username, "from": settings.From,
	}, map[string]string{"password": settings.Password})
}

// SMTP returns the stored relay settings with the decrypted password.
func (s *Service) SMTP(ctx context.Context) (SMTPSettings, bool, error) {
	var settings SMTPSettings
	config, secrets, err := s.load(ctx, ProviderSMTP)
	if errors.Is(err, ErrNotConfigured) {
		return SMTPSettings{}, false, nil
	}
	if err != nil {
		return SMTPSettings{}, false, err
	}
	settings.Host, settings.Username, settings.From = config["host"], config["username"], config["from"]
	settings.Password = secrets["password"]
	if raw := config["port"]; raw != "" {
		port, err := fmt.Sscanf(raw, "%d", &settings.Port)
		if err != nil || port != 1 {
			return SMTPSettings{}, false, fmt.Errorf("%w: port", ErrInvalidSettings)
		}
	}
	return settings, settings.Valid(), nil
}

// CloudflareConfigured reports whether DNS integration credentials exist.
func (s *Service) CloudflareConfigured(ctx context.Context) bool {
	var count int
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_integrations WHERE provider = 'cloudflare'").Scan(&count)
	})
	return err == nil && count > 0
}

// Configured reports whether a provider has stored settings.
func (s *Service) Configured(ctx context.Context, provider string) bool {
	switch provider {
	case ProviderS3, ProviderSMTP:
		_, _, err := s.load(ctx, provider)
		return err == nil
	default:
		return false
	}
}

// Test verifies one provider connection. Probe content is never persisted.
func (s *Service) Test(ctx context.Context, provider string) error {
	switch provider {
	case "cloudflare":
		return fmt.Errorf("%w: cloudflare requires zone credentials", ErrProviderUnsupported)
	case ProviderS3:
		settings, ok, err := s.S3(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotConfigured
		}
		return s.agent(ctx, "integration.test_s3", struct {
			Settings backups.RemoteSettings `json:"settings"`
			Probe    string                 `json:"probe"`
		}{settings, "tompanel-probe-" + fmt.Sprint(s.now().UnixNano())}, &struct{}{})
	case ProviderSMTP:
		settings, ok, err := s.SMTP(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotConfigured
		}
		return s.smtpDial(ctx, settings)
	default:
		return ErrProviderUnsupported
	}
}

// SendAlert delivers one bounded notification. Provider errors keep request
// identifiers but never leak recipients or secrets.
func (s *Service) SendAlert(ctx context.Context, alert Alert) error {
	if len(alert.Subject) > 200 || len(alert.Body) > 2000 {
		return errors.New("alert exceeds size bounds")
	}
	switch alert.Kind {
	case "job_failed", "security", "recovery":
	default:
		return errors.New("alert kind is unsupported")
	}
	settings, ok, err := s.SMTP(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotConfigured
	}
	return s.smtpDial(ctx, settings)
}

func (s *Service) save(ctx context.Context, provider string, config, secrets map[string]string) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}
	secretsJSON, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	encrypted, err := s.store.Encrypt(secretsJSON, []byte("tompanel.integration."+provider))
	if err != nil {
		return err
	}
	now := s.now().UTC().Unix()
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO integrations(provider, config_json, secret_ciphertext, updated_at)
			VALUES (?, ?, ?, ?) ON CONFLICT(provider) DO UPDATE SET config_json = excluded.config_json,
			secret_ciphertext = excluded.secret_ciphertext, updated_at = excluded.updated_at`, provider, string(configJSON), encrypted, now)
		return err
	})
}

func (s *Service) load(ctx context.Context, provider string) (map[string]string, map[string]string, error) {
	var configJSON string
	var encrypted []byte
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT config_json, secret_ciphertext FROM integrations WHERE provider = ?", provider).
			Scan(&configJSON, &encrypted)
	})
	if errors.Is(err, sql.ErrNoRows) || encrypted == nil {
		return nil, nil, ErrNotConfigured
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load integration %s: %w", provider, err)
	}
	var config, secrets map[string]string
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, nil, fmt.Errorf("%w: %s config", ErrInvalidSettings, provider)
	}
	decrypted, err := s.store.Decrypt(encrypted, []byte("tompanel.integration."+provider))
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(decrypted, &secrets); err != nil {
		return nil, nil, fmt.Errorf("%w: %s secrets", ErrInvalidSettings, provider)
	}
	return config, secrets, nil
}
