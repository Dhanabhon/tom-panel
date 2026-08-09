package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

const (
	setupLifetime     = 15 * time.Minute
	challengeLifetime = 5 * time.Minute
	idleLifetime      = 30 * time.Minute
	absoluteLifetime  = 12 * time.Hour
	stepUpLifetime    = 5 * time.Minute
	maxThrottleKeys   = 1024
	maxChallenges     = 128
	factorThrottleMax = time.Minute
)

const (
	setupSettingKey      = "auth.setup"
	totpReplaySettingKey = "auth.totp.last_counter"
	totpAAD              = "admins:1:totp_secret"
)

var (
	ErrAlreadySetup       = errors.New("administrator setup is unavailable")
	ErrInvalidSetupToken  = errors.New("setup token is invalid or expired")
	ErrInvalidCredentials = errors.New("invalid username, password, or verification code")
	ErrInvalidSession     = errors.New("session is invalid or expired")
)

type Enrollment struct {
	TOTPSecret    string   `json:"totp_secret"`
	TOTPURI       string   `json:"totp_uri"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type Session struct {
	ID                string    `json:"-"`
	CSRFToken         string    `json:"-"`
	IdleExpiresAt     time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
}

type loginError struct{ retryAfter time.Duration }

func (e *loginError) Error() string { return ErrInvalidCredentials.Error() }
func (e *loginError) Unwrap() error { return ErrInvalidCredentials }

func RetryAfter(err error) time.Duration {
	var loginErr *loginError
	if errors.As(err, &loginErr) {
		return loginErr.retryAfter
	}
	return 0
}

type setupRecord struct {
	Hash      string `json:"hash"`
	ExpiresAt int64  `json:"expires_at"`
}

type challenge struct {
	adminID           int64
	credentialVersion int64
	factorKeys        []string
	expires           time.Time
	attempts          int
	inUse             bool
}

type throttleState struct {
	attempts int
	until    time.Time
	seen     time.Time
}

type Service struct {
	store *store.Store
	now   func() time.Time

	mu         sync.Mutex
	challenges map[string]challenge
	throttles  map[string]throttleState
	dummyHash  []byte
}

func New(store *store.Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	dummy, err := hashPassword("tompanel constant shape password")
	if err != nil {
		dummy = []byte("invalid hash")
	}
	return &Service{store: store, now: now, challenges: make(map[string]challenge), throttles: make(map[string]throttleState), dummyHash: dummy}
}

func (s *Service) CreateSetupToken(ctx context.Context) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	digest := tokenHash(token)
	record, err := json.Marshal(setupRecord{Hash: base64.RawStdEncoding.EncodeToString(digest[:]), ExpiresAt: s.now().Add(setupLifetime).Unix()})
	if err != nil {
		return "", fmt.Errorf("encode setup token: %w", err)
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		var admins int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&admins); err != nil {
			return fmt.Errorf("check administrator: %w", err)
		}
		if admins != 0 {
			return ErrAlreadySetup
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, setupSettingKey, string(record), s.now().Unix())
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) CompleteSetup(ctx context.Context, token, username, password string) (Enrollment, error) {
	if err := s.preflightSetupToken(ctx, token); err != nil {
		return Enrollment{}, err
	}
	if err := validateUsername(username); err != nil {
		return Enrollment{}, err
	}
	if err := validatePassword(password, username); err != nil {
		return Enrollment{}, err
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return Enrollment{}, err
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	recoveryCodes, recoveryHashes, err := newRecoveryCodes()
	if err != nil {
		return Enrollment{}, err
	}
	encryptedSecret, err := s.store.Encrypt([]byte(secret), []byte(totpAAD))
	if err != nil {
		return Enrollment{}, err
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		if err := s.checkSetupTokenTx(ctx, tx, token); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO admins(id, username, password_hash, totp_secret, recovery_codes, created_at, updated_at)
			VALUES (1, ?, ?, ?, ?, ?, ?)`, username, passwordHash, encryptedSecret, encodeRecoveryHashes(recoveryHashes), s.now().Unix(), s.now().Unix())
		if err != nil {
			return ErrAlreadySetup
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return ErrAlreadySetup
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", setupSettingKey); err != nil {
			return fmt.Errorf("consume setup token: %w", err)
		}
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{TOTPSecret: secret, TOTPURI: totpURI(username, secret), RecoveryCodes: recoveryCodes}, nil
}

func (s *Service) preflightSetupToken(ctx context.Context, token string) error {
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		return s.checkSetupTokenTx(ctx, tx, token)
	})
}

func (s *Service) checkSetupTokenTx(ctx context.Context, tx *sql.Tx, token string) error {
	var admins int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&admins); err != nil {
		return fmt.Errorf("check administrator: %w", err)
	}
	if admins != 0 {
		return ErrAlreadySetup
	}
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", setupSettingKey).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidSetupToken
		}
		return fmt.Errorf("read setup token: %w", err)
	}
	var record setupRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return ErrInvalidSetupToken
	}
	want, err := base64.RawStdEncoding.DecodeString(record.Hash)
	digest := tokenHash(token)
	if err != nil || len(want) != sha256.Size || subtle.ConstantTimeCompare(digest[:], want) != 1 || !s.now().Before(time.Unix(record.ExpiresAt, 0)) {
		return ErrInvalidSetupToken
	}
	return nil
}

func (s *Service) Authenticate(ctx context.Context, username, password, remoteIP string) (string, error) {
	passwordKeys := []string{"ip:" + normalizeIP(remoteIP), accountThrottleKey(username)}
	if delay := s.throttled(passwordKeys); delay > 0 {
		return "", &loginError{retryAfter: delay}
	}
	var adminID int64
	var credentialVersion int64
	var storedUsername string
	passwordHash := s.dummyHash
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT id, username, password_hash, updated_at FROM admins WHERE id = 1").Scan(&adminID, &storedUsername, &passwordHash, &credentialVersion)
		if errors.Is(err, sql.ErrNoRows) {
			adminID = 0
			storedUsername = ""
			passwordHash = s.dummyHash
			return nil
		}
		return err
	})
	if err != nil {
		return "", fmt.Errorf("read administrator: %w", err)
	}
	usernameOK := constantStringEqual(strings.ToLower(username), strings.ToLower(storedUsername))
	passwordOK := passwordMatches(passwordHash, password)
	if adminID == 0 || !usernameOK || !passwordOK {
		s.recordFailure(passwordKeys)
		return "", &loginError{}
	}
	s.clearThrottle(passwordKeys)
	factorKeys := secondFactorThrottleKeys(username, remoteIP)
	if delay := s.throttled(factorKeys); delay > 0 {
		return "", &loginError{retryAfter: delay}
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.pruneChallengesLocked()
	s.challenges[tokenKey(token)] = challenge{adminID: adminID, credentialVersion: credentialVersion, factorKeys: factorKeys, expires: s.now().Add(challengeLifetime)}
	s.mu.Unlock()
	return token, nil
}

func (s *Service) VerifyTOTP(ctx context.Context, challengeToken, code string) (Session, error) {
	key := tokenKey(challengeToken)
	challengeRecord, ok := s.beginChallenge(key)
	if !ok {
		return Session{}, ErrInvalidCredentials
	}
	succeeded := false
	failedVerification := false
	defer func() { s.finishChallenge(key, succeeded, failedVerification) }()
	if delay := s.throttled(challengeRecord.factorKeys); delay > 0 {
		return Session{}, &loginError{retryAfter: delay}
	}
	sessionID, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	idleExpires := s.now().Add(idleLifetime)
	absoluteExpires := s.now().Add(absoluteLifetime)
	sessionDigest := tokenHash(sessionID)
	csrfDigest := tokenHash(csrfToken)
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		var encryptedSecret, recoveryCodes []byte
		var credentialVersion int64
		if err := tx.QueryRowContext(ctx, "SELECT totp_secret, recovery_codes, updated_at FROM admins WHERE id = ?", challengeRecord.adminID).Scan(&encryptedSecret, &recoveryCodes, &credentialVersion); err != nil || credentialVersion != challengeRecord.credentialVersion {
			return ErrInvalidCredentials
		}
		remaining, usedRecovery, err := s.verifySecondFactor(ctx, tx, encryptedSecret, recoveryCodes, code)
		if err != nil {
			return err
		}
		if usedRecovery {
			if _, err := tx.ExecContext(ctx, "UPDATE admins SET recovery_codes = ?, updated_at = max(updated_at + 1, ?) WHERE id = ?", remaining, s.now().Unix(), challengeRecord.adminID); err != nil {
				return fmt.Errorf("consume recovery code: %w", err)
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO sessions(id_hash, admin_id, csrf_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, sessionDigest[:], challengeRecord.adminID, csrfDigest[:], s.now().Unix(), s.now().Unix(), idleExpires.Unix(), absoluteExpires.Unix())
		return err
	})
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			failedVerification = true
			s.recordSecondFactorFailure(challengeRecord.factorKeys)
			return Session{}, ErrInvalidCredentials
		}
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	succeeded = true
	s.clearThrottle(challengeRecord.factorKeys)
	return Session{ID: sessionID, CSRFToken: csrfToken, IdleExpiresAt: idleExpires, AbsoluteExpiresAt: absoluteExpires}, nil
}

func (s *Service) SessionValid(ctx context.Context, sessionID string) bool {
	_, err := s.session(ctx, sessionID, true)
	return err == nil
}

func (s *Service) Logout(ctx context.Context, sessionID string) error {
	digest := tokenHash(sessionID)
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE id_hash = ?", digest[:])
		return err
	})
}

func (s *Service) StepUp(ctx context.Context, sessionID, password, code string) error {
	record, err := s.session(ctx, sessionID, false)
	if err != nil {
		return ErrInvalidCredentials
	}
	return s.store.Tx(ctx, func(tx *sql.Tx) error {
		var passwordHash, encryptedSecret []byte
		if err := tx.QueryRowContext(ctx, "SELECT password_hash, totp_secret FROM admins WHERE id = ?", record.adminID).Scan(&passwordHash, &encryptedSecret); err != nil {
			return ErrInvalidCredentials
		}
		passwordOK := passwordMatches(passwordHash, password)
		factorErr := s.verifyTOTPFactor(ctx, tx, encryptedSecret, code)
		if !passwordOK || factorErr != nil {
			return ErrInvalidCredentials
		}
		result, err := tx.ExecContext(ctx, "UPDATE sessions SET step_up_until = ? WHERE id_hash = ?", s.now().Add(stepUpLifetime).Unix(), record.idHash)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return ErrInvalidSession
		}
		return nil
	})
}

func (s *Service) ResetPassword(ctx context.Context, adminID int64, password string) error {
	var username string
	if err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT username FROM admins WHERE id = ?", adminID).Scan(&username)
	}); err != nil {
		return fmt.Errorf("read administrator: %w", err)
	}
	if err := validatePassword(password, username); err != nil {
		return err
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE admins SET password_hash = ?, recovery_codes = NULL, updated_at = max(updated_at + 1, ?) WHERE id = ?", passwordHash, s.now().Unix(), adminID)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id = ?", adminID)
		return err
	})
	if err == nil {
		s.invalidateChallenges(adminID)
	}
	return err
}

func (s *Service) SetUsername(ctx context.Context, adminID int64, username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE admins SET username = ?, recovery_codes = NULL, updated_at = max(updated_at + 1, ?) WHERE id = ?", username, s.now().Unix(), adminID)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return sql.ErrNoRows
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id = ?", adminID)
		return err
	})
	if err == nil {
		s.invalidateChallenges(adminID)
	}
	return err
}

func (s *Service) ResetTOTP(ctx context.Context, adminID int64) (Enrollment, error) {
	var username string
	if err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT username FROM admins WHERE id = ?", adminID).Scan(&username)
	}); err != nil {
		return Enrollment{}, err
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return Enrollment{}, err
	}
	encrypted, err := s.store.Encrypt([]byte(secret), []byte(totpAAD))
	if err != nil {
		return Enrollment{}, err
	}
	err = s.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE admins SET totp_secret = ?, recovery_codes = ?, updated_at = max(updated_at + 1, ?) WHERE id = ?", encrypted, encodeRecoveryHashes(hashes), s.now().Unix(), adminID)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return sql.ErrNoRows
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id = ?", adminID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", totpReplaySettingKey)
		return err
	})
	if err != nil {
		return Enrollment{}, err
	}
	s.invalidateChallenges(adminID)
	return Enrollment{TOTPSecret: secret, TOTPURI: totpURI(username, secret), RecoveryCodes: codes}, nil
}

type sessionRecord struct {
	adminID     int64
	idHash      []byte
	csrfHash    []byte
	idleExpires time.Time
	absExpires  time.Time
	stepUpUntil time.Time
}

func (s *Service) session(ctx context.Context, sessionID string, touch bool) (sessionRecord, error) {
	digest := tokenHash(sessionID)
	var record sessionRecord
	record.idHash = digest[:]
	expired := false
	err := s.store.Tx(ctx, func(tx *sql.Tx) error {
		var idle, absolute int64
		var stepUp sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT admin_id, csrf_hash, idle_expires_at, absolute_expires_at, step_up_until
			FROM sessions WHERE id_hash = ?`, digest[:]).Scan(&record.adminID, &record.csrfHash, &idle, &absolute, &stepUp); err != nil {
			return ErrInvalidSession
		}
		record.idleExpires = time.Unix(idle, 0)
		record.absExpires = time.Unix(absolute, 0)
		if stepUp.Valid {
			record.stepUpUntil = time.Unix(stepUp.Int64, 0)
		}
		if !s.now().Before(record.idleExpires) || !s.now().Before(record.absExpires) {
			expired = true
			_, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE id_hash = ?", digest[:])
			return err
		}
		if touch {
			nextIdle := s.now().Add(idleLifetime)
			if nextIdle.After(record.absExpires) {
				nextIdle = record.absExpires
			}
			if _, err := tx.ExecContext(ctx, "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id_hash = ?", s.now().Unix(), nextIdle.Unix(), digest[:]); err != nil {
				return err
			}
			record.idleExpires = nextIdle
		}
		return nil
	})
	if err != nil {
		return sessionRecord{}, err
	}
	if expired {
		return sessionRecord{}, ErrInvalidSession
	}
	return record, nil
}

func (s *Service) verifySecondFactor(ctx context.Context, tx *sql.Tx, encryptedSecret, recoveryCodes []byte, code string) ([]byte, bool, error) {
	if err := s.verifyTOTPFactor(ctx, tx, encryptedSecret, code); err == nil {
		return recoveryCodes, false, nil
	} else if !errors.Is(err, ErrInvalidCredentials) {
		return nil, false, err
	}
	remaining, ok := consumeRecoveryCode(recoveryCodes, code)
	if !ok {
		return nil, false, ErrInvalidCredentials
	}
	return remaining, true, nil
}

func (s *Service) verifyTOTPFactor(ctx context.Context, tx *sql.Tx, encryptedSecret []byte, code string) error {
	secret, err := s.store.Decrypt(encryptedSecret, []byte(totpAAD))
	if err != nil {
		return ErrInvalidCredentials
	}
	defer clearBytes(secret)
	if counter, ok := matchingTOTPCounter(string(secret), code, s.now()); ok {
		lastCounter := int64(-1)
		var raw string
		err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", totpReplaySettingKey).Scan(&raw)
		if err == nil {
			parsed, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil {
				return ErrInvalidCredentials
			}
			lastCounter = parsed
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if counter <= lastCounter {
			return ErrInvalidCredentials
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, totpReplaySettingKey, strconv.FormatInt(counter, 10), s.now().Unix())
		return err
	}
	return ErrInvalidCredentials
}

func (s *Service) beginChallenge(key string) (challenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.challenges[key]
	if !ok || record.inUse || record.attempts >= 5 || !s.now().Before(record.expires) {
		delete(s.challenges, key)
		return challenge{}, false
	}
	record.inUse = true
	s.challenges[key] = record
	return record, true
}

func (s *Service) finishChallenge(key string, success, failedVerification bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if success {
		delete(s.challenges, key)
		return
	}
	record, ok := s.challenges[key]
	if !ok {
		return
	}
	record.inUse = false
	if failedVerification {
		record.attempts++
	}
	if record.attempts >= 5 {
		delete(s.challenges, key)
	} else {
		s.challenges[key] = record
	}
}

func (s *Service) invalidateChallenges(adminID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, record := range s.challenges {
		if record.adminID == adminID {
			delete(s.challenges, key)
		}
	}
}

func (s *Service) pruneChallengesLocked() {
	for key, record := range s.challenges {
		if !s.now().Before(record.expires) {
			delete(s.challenges, key)
		}
	}
	for len(s.challenges) >= maxChallenges {
		// ponytail: O(n) eviction is capped at 128 authenticated challenges; use an LRU only if this becomes measurable.
		var oldestKey string
		var oldest time.Time
		for key, record := range s.challenges {
			if oldestKey == "" || record.expires.Before(oldest) {
				oldestKey, oldest = key, record.expires
			}
		}
		delete(s.challenges, oldestKey)
	}
}

func (s *Service) throttled(keys []string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var delay time.Duration
	for _, key := range keys {
		if state, ok := s.throttles[key]; ok && s.now().Before(state.until) {
			if remaining := state.until.Sub(s.now()); remaining > delay {
				delay = remaining
			}
		}
	}
	return delay
}

func (s *Service) recordFailure(keys []string) {
	s.recordFailureWithBounds(keys, 250*time.Millisecond, 8*time.Second)
}

func (s *Service) recordSecondFactorFailure(keys []string) {
	s.recordFailureWithBounds(keys, time.Second, factorThrottleMax)
}

func (s *Service) recordFailureWithBounds(keys []string, base, maximum time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		state := s.throttles[key]
		state.attempts++
		delay := base
		for attempt := 1; attempt < state.attempts && delay < maximum; attempt++ {
			delay *= 2
			if delay > maximum {
				delay = maximum
			}
		}
		state.until = s.now().Add(delay)
		state.seen = s.now()
		s.throttles[key] = state
	}
	for len(s.throttles) > maxThrottleKeys {
		// ponytail: O(n) eviction is capped at 1024 keys; use an LRU only if abuse-path profiling warrants it.
		var oldestKey string
		var oldest time.Time
		for key, state := range s.throttles {
			if oldestKey == "" || state.seen.Before(oldest) {
				oldestKey, oldest = key, state.seen
			}
		}
		delete(s.throttles, oldestKey)
	}
}

func (s *Service) clearThrottle(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		delete(s.throttles, key)
	}
}

func validateUsername(username string) error {
	if !utf8.ValidString(username) || username == "" || utf8.RuneCountInString(username) > 64 || strings.TrimSpace(username) != username {
		return errors.New("username must be 1-64 characters without surrounding spaces")
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return errors.New("username must not contain control characters")
		}
	}
	return nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	defer clearBytes(value)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenHash(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }
func tokenKey(token string) string {
	digest := tokenHash(token)
	return base64.RawStdEncoding.EncodeToString(digest[:])
}

func accountThrottleKey(username string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(username)))
	return "account:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func secondFactorThrottleKeys(username, remoteIP string) []string {
	return []string{"factor-ip:" + normalizeIP(remoteIP), "factor-" + accountThrottleKey(username)}
}

func constantStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

func normalizeIP(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if parsed := net.ParseIP(remote); parsed != nil {
		return parsed.String()
	}
	return "unknown"
}
