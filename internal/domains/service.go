package domains

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/sites"
	"github.com/Dhanabhon/tom-panel/internal/store"
)

type Challenge string

const (
	ChallengeHTTP01     Challenge = "http-01"
	ChallengeCloudflare Challenge = "cloudflare"
)

type CertificateState string

const (
	CertificatePending       CertificateState = "pending"
	CertificateActive        CertificateState = "active"
	CertificateRenewalFailed CertificateState = "renewal_failed"
	CertificateExpired       CertificateState = "expired"
)

var (
	ErrDomainNotFound   = errors.New("domain not found")
	ErrExternalResource = errors.New("resource is not managed by TomPanel")
	ErrDNSNotConfigured = errors.New("DNS provider is not configured")
)

type Domain struct {
	ID, SiteID, Hostname, Kind, RedirectTarget string
	Port                                       int
}

type Certificate struct {
	ID, SiteID, CertificatePath, PrivateKeyPath, Email string
	Hostnames                                          []string
	Challenge                                          Challenge
	State                                              CertificateState
	NotBefore, NotAfter                                time.Time
	RenewalAttempts                                    int
}

type CertificateRequest struct {
	SiteID    string
	Hostnames []string
	Challenge Challenge
	Email     string
}

type certificateIssueInput struct {
	SiteID    string    `json:"site_id"`
	Hostnames []string  `json:"hostnames"`
	Challenge Challenge `json:"challenge"`
	Email     string    `json:"email"`
	APIToken  string    `json:"api_token,omitempty"`
}

type certificateIssueResult struct {
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	NotBefore       int64  `json:"not_before"`
	NotAfter        int64  `json:"not_after"`
}

type certificateActivateInput struct {
	SiteID          string `json:"site_id"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type certificateActivateResult struct {
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type agentCaller func(context.Context, string, any, any) error

type Service struct {
	store       *store.Store
	httpClient  *http.Client
	agentCall   agentCaller
	lookupIP    func(context.Context, string) ([]netip.Addr, error)
	lookupTXT   func(context.Context, string) ([]string, error)
	lookupCNAME func(context.Context, string) (string, error)
	now         func() time.Time
}

func NewService(database *store.Store, agent *agentapi.Client) *Service {
	call := agentCaller(func(context.Context, string, any, any) error {
		return errors.New("privileged agent is unavailable")
	})
	if agent != nil {
		call = agent.Call
	}
	return &Service{
		store: database, httpClient: &http.Client{Timeout: 10 * time.Second},
		agentCall: call,
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		lookupTXT:   net.DefaultResolver.LookupTXT,
		lookupCNAME: net.DefaultResolver.LookupCNAME,
		now:         time.Now,
	}
}

func (s *Service) AddHostname(ctx context.Context, siteID, hostname string, port int) (Domain, error) {
	return s.addDomain(ctx, siteID, hostname, port, "subdomain", "")
}

func (s *Service) Park(ctx context.Context, siteID, hostname string, port int) (Domain, error) {
	return s.addDomain(ctx, siteID, hostname, port, "parked", "")
}

func (s *Service) Redirect(ctx context.Context, siteID, hostname string, port int, target string) (Domain, error) {
	normalizedTarget, err := sites.NormalizeHostname(target)
	if err != nil {
		return Domain{}, err
	}
	return s.addDomain(ctx, siteID, hostname, port, "redirect", normalizedTarget)
}

func (s *Service) addDomain(ctx context.Context, siteID, hostname string, port int, kind, target string) (Domain, error) {
	hostname, err := sites.NormalizeHostname(hostname)
	if err != nil || port < 1 || port > 65535 || len(siteID) != 32 {
		return Domain{}, errors.New("domain input is invalid")
	}
	id, err := domainID()
	if err != nil {
		return Domain{}, err
	}
	now := s.now().UTC().Unix()
	domain := Domain{ID: id, SiteID: siteID, Hostname: hostname, Port: port, Kind: kind, RedirectTarget: target}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO domains(id, site_id, hostname, port, kind, redirect_target, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`, id, siteID, hostname, port, kind, target, now, now)
		return err
	})
	return domain, err
}

func (s *Service) ListDomains(ctx context.Context) ([]Domain, error) {
	var result []Domain
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, site_id, hostname, port, kind, COALESCE(redirect_target, '')
			FROM domains ORDER BY hostname, port`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var domain Domain
			if err := rows.Scan(&domain.ID, &domain.SiteID, &domain.Hostname, &domain.Port, &domain.Kind, &domain.RedirectTarget); err != nil {
				return err
			}
			result = append(result, domain)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) IssueCertificate(ctx context.Context, request CertificateRequest) (Certificate, error) {
	hostnames, err := normalizeHostnameSet(request.Hostnames)
	if err != nil || len(request.SiteID) != 32 || request.Email == "" || request.Challenge != ChallengeHTTP01 && request.Challenge != ChallengeCloudflare {
		return Certificate{}, errors.New("certificate request is invalid")
	}
	input := certificateIssueInput{SiteID: request.SiteID, Hostnames: hostnames, Challenge: request.Challenge, Email: request.Email}
	if request.Challenge == ChallengeCloudflare {
		_, token, err := s.cloudflareCredentials(ctx)
		if err != nil {
			return Certificate{}, err
		}
		input.APIToken = token
	}
	id, err := domainID()
	if err != nil {
		return Certificate{}, err
	}
	certificate := Certificate{
		ID: id, SiteID: request.SiteID, Hostnames: hostnames, Challenge: request.Challenge,
		Email: request.Email, State: CertificatePending,
	}
	if err := s.saveCertificate(ctx, certificate); err != nil {
		return Certificate{}, err
	}
	var issued certificateIssueResult
	if err := s.agentCall(ctx, "certificate.issue", input, &issued); err != nil {
		return Certificate{}, err
	}
	var active certificateActivateResult
	if err := s.agentCall(ctx, "certificate.activate", certificateActivateInput{
		SiteID: request.SiteID, CertificatePath: issued.CertificatePath, PrivateKeyPath: issued.PrivateKeyPath,
	}, &active); err != nil {
		return Certificate{}, err
	}
	certificate.CertificatePath, certificate.PrivateKeyPath = active.CertificatePath, active.PrivateKeyPath
	certificate.State = CertificateActive
	certificate.NotBefore, certificate.NotAfter = time.Unix(issued.NotBefore, 0).UTC(), time.Unix(issued.NotAfter, 0).UTC()
	if err := s.saveCertificate(ctx, certificate); err != nil {
		return Certificate{}, err
	}
	return certificate, nil
}

func (s *Service) RenewDue(ctx context.Context, within time.Duration) error {
	var due []Certificate
	now := s.now().UTC()
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, site_id, hostname_set, challenge, email, certificate_path,
			private_key_path, state, not_before, not_after, renewal_attempts
			FROM certificates WHERE not_after <= ? AND (state = 'active' OR (state = 'renewal_failed' AND COALESCE(next_renewal_attempt, 0) <= ?))`, now.Add(within).Unix(), now.Unix())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			certificate, err := scanCertificate(rows)
			if err != nil {
				return err
			}
			due = append(due, certificate)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	var failures []error
	for _, certificate := range due {
		_, err := s.renew(ctx, certificate)
		if err != nil {
			failures = append(failures, err)
			_ = s.recordRenewalFailure(ctx, certificate)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) renew(ctx context.Context, certificate Certificate) (Certificate, error) {
	input := certificateIssueInput{SiteID: certificate.SiteID, Hostnames: certificate.Hostnames, Challenge: certificate.Challenge, Email: certificate.Email}
	if certificate.Challenge == ChallengeCloudflare {
		_, token, err := s.cloudflareCredentials(ctx)
		if err != nil {
			return Certificate{}, err
		}
		input.APIToken = token
	}
	var issued certificateIssueResult
	if err := s.agentCall(ctx, "certificate.issue", input, &issued); err != nil {
		return Certificate{}, err
	}
	var active certificateActivateResult
	if err := s.agentCall(ctx, "certificate.activate", certificateActivateInput{
		SiteID: certificate.SiteID, CertificatePath: issued.CertificatePath, PrivateKeyPath: issued.PrivateKeyPath,
	}, &active); err != nil {
		return Certificate{}, err
	}
	certificate.CertificatePath, certificate.PrivateKeyPath = active.CertificatePath, active.PrivateKeyPath
	certificate.NotBefore, certificate.NotAfter = time.Unix(issued.NotBefore, 0).UTC(), time.Unix(issued.NotAfter, 0).UTC()
	certificate.State, certificate.RenewalAttempts = CertificateActive, 0
	return certificate, s.saveCertificate(ctx, certificate)
}

func (s *Service) recordRenewalFailure(ctx context.Context, certificate Certificate) error {
	attempts := certificate.RenewalAttempts + 1
	delay := time.Hour << min(attempts-1, 4)
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE certificates SET state = 'renewal_failed', renewal_attempts = ?,
			next_renewal_attempt = ?, updated_at = ? WHERE id = ?`, attempts, s.now().Add(delay).Unix(), s.now().Unix(), certificate.ID)
		return err
	})
}

func (s *Service) saveCertificate(ctx context.Context, certificate Certificate) error {
	hostnames, err := json.Marshal(certificate.Hostnames)
	if err != nil {
		return err
	}
	now := s.now().UTC().Unix()
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO certificates
			(id, site_id, hostname_set, challenge, email, certificate_path, private_key_path, state,
			 not_before, not_after, renewal_attempts, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET certificate_path=excluded.certificate_path,
			 private_key_path=excluded.private_key_path, state=excluded.state, not_before=excluded.not_before,
			 not_after=excluded.not_after, renewal_attempts=excluded.renewal_attempts,
			 next_renewal_attempt=NULL, updated_at=excluded.updated_at`,
			certificate.ID, certificate.SiteID, string(hostnames), certificate.Challenge, certificate.Email,
			certificate.CertificatePath, certificate.PrivateKeyPath, certificate.State,
			certificate.NotBefore.Unix(), certificate.NotAfter.Unix(), certificate.RenewalAttempts, now, now); err != nil {
			return err
		}
		if certificate.State == CertificateActive && certificate.CertificatePath != "" {
			_, err := tx.ExecContext(ctx, `INSERT INTO managed_resources(kind, external_id, path, created_at)
				VALUES ('certificate', ?, ?, ?) ON CONFLICT DO NOTHING`, certificate.ID, certificate.CertificatePath, now)
			return err
		}
		return nil
	})
}

func (s *Service) Certificate(ctx context.Context, id string) (Certificate, error) {
	var certificate Certificate
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT id, site_id, hostname_set, challenge, email, certificate_path,
			private_key_path, state, not_before, not_after, renewal_attempts FROM certificates WHERE id = ?`, id)
		var err error
		certificate, err = scanCertificate(row)
		return err
	})
	return certificate, err
}

type scanner interface{ Scan(...any) error }

func scanCertificate(row scanner) (Certificate, error) {
	var certificate Certificate
	var hostnames string
	var notBefore, notAfter int64
	err := row.Scan(&certificate.ID, &certificate.SiteID, &hostnames, &certificate.Challenge, &certificate.Email,
		&certificate.CertificatePath, &certificate.PrivateKeyPath, &certificate.State, &notBefore, &notAfter, &certificate.RenewalAttempts)
	if err != nil {
		return Certificate{}, err
	}
	if err := json.Unmarshal([]byte(hostnames), &certificate.Hostnames); err != nil {
		return Certificate{}, err
	}
	certificate.NotBefore, certificate.NotAfter = time.Unix(notBefore, 0).UTC(), time.Unix(notAfter, 0).UTC()
	return certificate, nil
}

func normalizeHostnameSet(values []string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		wildcard := strings.HasPrefix(strings.TrimSpace(value), "*.")
		hostname, err := sites.NormalizeHostname(strings.TrimPrefix(strings.TrimSpace(value), "*."))
		if err != nil {
			return nil, err
		}
		if wildcard {
			hostname = "*." + hostname
		}
		if !seen[hostname] {
			seen[hostname] = true
			result = append(result, hostname)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("hostname set is empty")
	}
	sort.Strings(result)
	return result, nil
}

func domainID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate domain ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
