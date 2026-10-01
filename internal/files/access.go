package files

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

// AccountState describes the SFTP lifecycle stored per site.
type AccountState string

const (
	AccountActive   AccountState = "active"
	AccountDisabled AccountState = "disabled"
)

// Account is the per-site SFTP account record.
type Account struct {
	ID          string       `json:"id"`
	SiteID      string       `json:"site_id"`
	Username    string       `json:"username"`
	State       AccountState `json:"state"`
	PasswordSet bool         `json:"password_set"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Key is one authorized SSH public key of an account.
type Key struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	PublicKey   string    `json:"public_key"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuditEvent records who performed a direct (non-job) access mutation.
type AuditEvent struct {
	AdminID int64
	Action  string
	Detail  json.RawMessage
}

var (
	ErrAccountNotFound  = errors.New("sftp account not found")
	ErrKeyNotFound      = errors.New("sftp key not found")
	ErrAccountRequired  = errors.New("sftp account must be enabled before this operation")
	passwordAlphabet    = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	passwordLength      = 24
	siteUsernamePrefix  = "tp_"
)

// AccessService combines SFTP account state with privileged agent calls.
type AccessService struct {
	store     *store.Store
	now       func() time.Time
	agentCall func(ctx context.Context, operation string, input, output any) error
}

// NewAccessService builds the access service. A nil agent client keeps the
// panel functional for reads while privileged operations fail closed.
func NewAccessService(database *store.Store, agentCaller func(ctx context.Context, operation string, input, output any) error) *AccessService {
	call := agentCaller
	if call == nil {
		call = func(context.Context, string, any, any) error {
			return errors.New("privileged agent is unavailable")
		}
	}
	return &AccessService{store: database, now: time.Now, agentCall: call}
}

// SiteUsername derives the fixed system account name of a site.
func SiteUsername(siteID string) (string, error) {
	if !ValidSiteID(siteID) {
		return "", ErrUnsafePath
	}
	return siteUsernamePrefix + siteID[:16], nil
}

// Enable provisions the site SFTP account and grants panel filesystem ACLs.
func (s *AccessService) Enable(ctx context.Context, siteID string, audit *AuditEvent) (Account, error) {
	username, err := SiteUsername(siteID)
	if err != nil {
		return Account{}, err
	}
	if err := s.agentCall(ctx, "sftp.ensure_account", struct {
		SiteID string `json:"site_id"`
	}{SiteID: siteID}, &struct{}{}); err != nil {
		return Account{}, err
	}
	if err := s.agentCall(ctx, "file.grant_panel_access", struct {
		SiteID string `json:"site_id"`
	}{SiteID: siteID}, &struct{}{}); err != nil {
		return Account{}, err
	}
	account, err := s.upsertAccount(ctx, siteID, username, AccountActive)
	if err != nil {
		return Account{}, err
	}
	if audit != nil {
		if err := s.WriteAudit(ctx, siteID, *audit); err != nil {
			return Account{}, err
		}
	}
	return account, nil
}

// Disable removes SFTP access while keeping the account record for history.
func (s *AccessService) Disable(ctx context.Context, siteID string, audit *AuditEvent) error {
	if _, err := SiteUsername(siteID); err != nil {
		return err
	}
	if _, _, err := s.Get(ctx, siteID); err != nil {
		return err
	}
	if err := s.agentCall(ctx, "sftp.disable_account", struct {
		SiteID string `json:"site_id"`
	}{SiteID: siteID}, &struct{}{}); err != nil {
		return err
	}
	if err := s.setAccountState(ctx, siteID, AccountDisabled); err != nil {
		return err
	}
	if audit != nil {
		if err := s.WriteAudit(ctx, siteID, *audit); err != nil {
			return err
		}
	}
	return nil
}

// RotatePassword generates a fresh password, applies it through the agent,
// and returns it exactly once for display.
func (s *AccessService) RotatePassword(ctx context.Context, siteID string, audit *AuditEvent) (string, error) {
	account, _, err := s.Get(ctx, siteID)
	if err != nil {
		return "", err
	}
	if account.State != AccountActive {
		return "", ErrAccountRequired
	}
	password, err := generatePassword()
	if err != nil {
		return "", err
	}
	if err := s.agentCall(ctx, "sftp.rotate_password", struct {
		SiteID   string `json:"site_id"`
		Password string `json:"password"`
	}{SiteID: siteID, Password: password}, &struct{}{}); err != nil {
		return "", err
	}
	if err := s.markPasswordSet(ctx, siteID); err != nil {
		return "", err
	}
	if audit != nil {
		if err := s.WriteAudit(ctx, siteID, *audit); err != nil {
			return "", err
		}
	}
	return password, nil
}

// AddKey authorizes one public key and returns its stored record.
func (s *AccessService) AddKey(ctx context.Context, siteID, publicKey string, audit *AuditEvent) (Key, error) {
	account, _, err := s.Get(ctx, siteID)
	if err != nil {
		return Key{}, err
	}
	if account.State != AccountActive {
		return Key{}, ErrAccountRequired
	}
	var result struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := s.agentCall(ctx, "sftp.add_key", struct {
		SiteID    string `json:"site_id"`
		PublicKey string `json:"public_key"`
	}{SiteID: siteID, PublicKey: publicKey}, &result); err != nil {
		return Key{}, err
	}
	keyType := keyTypeOf(publicKey)
	key, err := s.insertKey(ctx, account.ID, keyType, result.Fingerprint, publicKey)
	if err != nil {
		return Key{}, err
	}
	if audit != nil {
		if err := s.WriteAudit(ctx, siteID, *audit); err != nil {
			return Key{}, err
		}
	}
	return key, nil
}

// RemoveKey drops one authorized public key.
func (s *AccessService) RemoveKey(ctx context.Context, siteID, fingerprint string, audit *AuditEvent) error {
	account, _, err := s.Get(ctx, siteID)
	if err != nil {
		return err
	}
	if account.State != AccountActive {
		return ErrAccountRequired
	}
	if err := s.agentCall(ctx, "sftp.remove_key", struct {
		SiteID      string `json:"site_id"`
		Fingerprint string `json:"fingerprint"`
	}{SiteID: siteID, Fingerprint: fingerprint}, &struct{}{}); err != nil {
		return err
	}
	if err := s.deleteKey(ctx, account.ID, fingerprint); err != nil {
		return err
	}
	if audit != nil {
		if err := s.WriteAudit(ctx, siteID, *audit); err != nil {
			return err
		}
	}
	return nil
}

// Get returns the account and its keys for a site.
func (s *AccessService) Get(ctx context.Context, siteID string) (Account, []Key, error) {
	var account Account
	var createdAt, updatedAt int64
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, site_id, username, state, password_set, created_at, updated_at
			FROM sftp_accounts WHERE site_id = ?`, siteID).Scan(
			&account.ID, &account.SiteID, &account.Username, &account.State, &account.PasswordSet, &createdAt, &updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, nil, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, nil, fmt.Errorf("get sftp account: %w", err)
	}
	account.CreatedAt, account.UpdatedAt = time.Unix(createdAt, 0).UTC(), time.Unix(updatedAt, 0).UTC()
	keys, err := s.listKeys(ctx, account.ID)
	if err != nil {
		return Account{}, nil, err
	}
	return account, keys, nil
}

func (s *AccessService) listKeys(ctx context.Context, accountID string) ([]Key, error) {
	var keys []Key
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, fingerprint, key_type, public_key, created_at
			FROM sftp_keys WHERE account_id = ? ORDER BY created_at, id`, accountID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key Key
			var createdAt int64
			if err := rows.Scan(&key.ID, &key.Fingerprint, &key.KeyType, &key.PublicKey, &createdAt); err != nil {
				return err
			}
			key.CreatedAt = time.Unix(createdAt, 0).UTC()
			keys = append(keys, key)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list sftp keys: %w", err)
	}
	return keys, nil
}

func (s *AccessService) upsertAccount(ctx context.Context, siteID, username string, state AccountState) (Account, error) {
	id, err := newAccessID()
	if err != nil {
		return Account{}, err
	}
	now := s.now().UTC().Truncate(time.Second)
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sftp_accounts(id, site_id, username, state, password_set, created_at, updated_at)
			VALUES (?, ?, ?, ?, 0, ?, ?)
			ON CONFLICT(site_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`,
			id, siteID, username, state, now.Unix(), now.Unix())
		return err
	})
	if err != nil {
		return Account{}, fmt.Errorf("save sftp account: %w", err)
	}
	account, _, err := s.Get(ctx, siteID)
	return account, err
}

func (s *AccessService) setAccountState(ctx context.Context, siteID string, state AccountState) error {
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE sftp_accounts SET state = ?, updated_at = ? WHERE site_id = ?`,
			state, s.now().UTC().Unix(), siteID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrAccountNotFound
		}
		return nil
	})
}

func (s *AccessService) markPasswordSet(ctx context.Context, siteID string) error {
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE sftp_accounts SET password_set = 1, updated_at = ? WHERE site_id = ?`,
			s.now().UTC().Unix(), siteID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrAccountNotFound
		}
		return nil
	})
}

func (s *AccessService) insertKey(ctx context.Context, accountID, keyType, fingerprint, publicKey string) (Key, error) {
	id, err := newAccessID()
	if err != nil {
		return Key{}, err
	}
	key := Key{ID: id, KeyType: keyType, Fingerprint: fingerprint, PublicKey: publicKey, CreatedAt: s.now().UTC().Truncate(time.Second)}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sftp_keys(id, account_id, key_type, fingerprint, public_key, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, key.ID, accountID, keyType, fingerprint, publicKey, key.CreatedAt.Unix())
		return err
	})
	if err != nil {
		return Key{}, fmt.Errorf("save sftp key: %w", err)
	}
	return key, nil
}

func (s *AccessService) deleteKey(ctx context.Context, accountID, fingerprint string) error {
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM sftp_keys WHERE account_id = ? AND fingerprint = ?`, accountID, fingerprint)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrKeyNotFound
		}
		return nil
	})
}

func (s *AccessService) WriteAudit(ctx context.Context, siteID string, audit AuditEvent) error {
	if audit.AdminID < 1 || audit.Action == "" {
		return errors.New("audit administrator and action are required")
	}
	detail := audit.Detail
	if len(detail) == 0 || !json.Valid(detail) {
		detail = json.RawMessage(`{}`)
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(admin_id, action, target_kind, target_id, detail_json, created_at)
			VALUES (?, ?, 'sftp_account', ?, ?, ?)`, audit.AdminID, audit.Action, siteID, []byte(detail), s.now().UTC().Unix())
		return err
	})
}

func generatePassword() (string, error) {
	var builder strings.Builder
	for i := 0; i < passwordLength; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordAlphabet))))
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		builder.WriteByte(passwordAlphabet[index.Int64()])
	}
	return builder.String(), nil
}

func keyTypeOf(publicKey string) string {
	fields := strings.Fields(publicKey)
	if len(fields) == 0 || len(fields[0]) > 64 {
		return ""
	}
	return fields[0]
}

func newAccessID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
