package domains

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/Dhanabhon/tom-panel/internal/sites"
)

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

type DNSRecord struct {
	ID, SiteID, Type, Hostname, Content, Provider, ProviderID string
	Managed                                                   bool
}

type DNSInstruction struct {
	Hostname string
	Type     string
	Value    string
}

func ManualDNS(hostname, recordType, value string) (DNSInstruction, error) {
	hostname, err := sites.NormalizeHostname(hostname)
	if err != nil {
		return DNSInstruction{}, err
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	value = strings.TrimSpace(value)
	switch recordType {
	case "A":
		if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
			return DNSInstruction{}, errors.New("A record requires an IPv4 address")
		}
	case "AAAA":
		if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
			return DNSInstruction{}, errors.New("AAAA record requires an IPv6 address")
		}
	case "CNAME":
		value, err = sites.NormalizeHostname(value)
		if err != nil {
			return DNSInstruction{}, err
		}
	case "TXT":
		if value == "" || len(value) > 1024 {
			return DNSInstruction{}, errors.New("TXT value is invalid")
		}
	default:
		return DNSInstruction{}, errors.New("DNS record type is unsupported")
	}
	return DNSInstruction{Hostname: hostname, Type: recordType, Value: value}, nil
}

func (s *Service) CheckDNS(ctx context.Context, instruction DNSInstruction) (bool, error) {
	validated, err := ManualDNS(instruction.Hostname, instruction.Type, instruction.Value)
	if err != nil {
		return false, err
	}
	switch validated.Type {
	case "A", "AAAA":
		addresses, err := s.lookupIP(ctx, validated.Hostname)
		if err != nil {
			return false, err
		}
		want, _ := netip.ParseAddr(validated.Value)
		for _, address := range addresses {
			if address.Unmap() == want.Unmap() {
				return true, nil
			}
		}
	case "CNAME":
		canonical, err := s.lookupCNAME(ctx, validated.Hostname)
		if err != nil {
			return false, err
		}
		canonical, err = sites.NormalizeHostname(canonical)
		return err == nil && canonical == validated.Value, err
	case "TXT":
		values, err := s.lookupTXT(ctx, validated.Hostname)
		if err != nil {
			return false, err
		}
		for _, value := range values {
			if value == validated.Value {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *Service) ConfigureCloudflare(ctx context.Context, zoneID, token string) error {
	zoneID, token = strings.TrimSpace(zoneID), strings.TrimSpace(token)
	if len(zoneID) < 8 || len(zoneID) > 64 || token == "" || len(token) > 512 {
		return errors.New("Cloudflare credentials are invalid")
	}
	ciphertext, err := s.store.Encrypt([]byte(token), []byte("cloudflare-api-token"))
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO dns_integrations(provider, zone_id, token_ciphertext, updated_at)
			VALUES ('cloudflare', ?, ?, ?) ON CONFLICT(provider) DO UPDATE SET
			zone_id=excluded.zone_id, token_ciphertext=excluded.token_ciphertext, updated_at=excluded.updated_at`,
			zoneID, ciphertext, s.now().UTC().Unix())
		return err
	})
}

func (s *Service) cloudflareCredentials(ctx context.Context) (string, string, error) {
	var zone string
	var ciphertext []byte
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT zone_id, token_ciphertext FROM dns_integrations WHERE provider = 'cloudflare'`).Scan(&zone, &ciphertext)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrDNSNotConfigured
	}
	if err != nil {
		return "", "", err
	}
	plain, err := s.store.Decrypt(ciphertext, []byte("cloudflare-api-token"))
	if err != nil {
		return "", "", err
	}
	return zone, string(plain), nil
}

func (s *Service) CreateDNS(ctx context.Context, record DNSRecord) (DNSRecord, error) {
	instruction, err := ManualDNS(record.Hostname, record.Type, record.Content)
	if err != nil || len(record.SiteID) != 32 {
		return DNSRecord{}, errors.New("DNS record is invalid")
	}
	id, err := domainID()
	if err != nil {
		return DNSRecord{}, err
	}
	zone, token, err := s.cloudflareCredentials(ctx)
	if err != nil {
		return DNSRecord{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"type": instruction.Type, "name": instruction.Hostname, "content": instruction.Value,
		"ttl": 1, "proxied": false, "comment": "TomPanel:" + id,
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cloudflareAPI+"/zones/"+url.PathEscape(zone)+"/dns_records", bytes.NewReader(body))
	if err != nil {
		return DNSRecord{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	var response struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := s.doCloudflare(request, &response); err != nil {
		return DNSRecord{}, err
	}
	record = DNSRecord{ID: id, SiteID: record.SiteID, Type: instruction.Type, Hostname: instruction.Hostname,
		Content: instruction.Value, Provider: "cloudflare", ProviderID: response.Result.ID, Managed: true}
	if record.ProviderID == "" {
		return DNSRecord{}, errors.New("Cloudflare returned an empty record ID")
	}
	return record, s.saveDNSRecord(ctx, record)
}

func (s *Service) DeleteDNS(ctx context.Context, id string) error {
	record, err := s.dnsRecord(ctx, id)
	if err != nil {
		return err
	}
	if !record.Managed {
		return ErrExternalResource
	}
	if record.Provider == "cloudflare" {
		zone, token, err := s.cloudflareCredentials(ctx)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodDelete, cloudflareAPI+"/zones/"+url.PathEscape(zone)+"/dns_records/"+url.PathEscape(record.ProviderID), nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		if err := s.doCloudflare(request, &struct{}{}); err != nil {
			return err
		}
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM dns_records WHERE id = ? AND managed = 1", id)
		return err
	})
}

func (s *Service) saveDNSRecord(ctx context.Context, record DNSRecord) error {
	now := s.now().UTC().Unix()
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO dns_records
			(id, site_id, record_type, hostname, content, provider, provider_record_id, managed, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?)`, record.ID, record.SiteID, record.Type,
			record.Hostname, record.Content, record.Provider, record.ProviderID, record.Managed, now, now)
		return err
	})
}

func (s *Service) dnsRecord(ctx context.Context, id string) (DNSRecord, error) {
	var record DNSRecord
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, site_id, record_type, hostname, content, provider,
			COALESCE(provider_record_id, ''), managed FROM dns_records WHERE id = ?`, id).
			Scan(&record.ID, &record.SiteID, &record.Type, &record.Hostname, &record.Content,
				&record.Provider, &record.ProviderID, &record.Managed)
	})
	return record, err
}

func (s *Service) doCloudflare(request *http.Request, output any) error {
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("Cloudflare returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}
