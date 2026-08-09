package auth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

func TestCredentialResetInvalidatesEverySession(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc, adminID, secret, recoveryCode := seededAuthWithRecoveryAt(t, &now)
	first := login(t, svc, secret)
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.VerifyTOTP(context.Background(), challenge, recoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(context.Background(), adminID, "a new long passphrase"); err != nil {
		t.Fatal(err)
	}
	if svc.SessionValid(context.Background(), first.ID) || svc.SessionValid(context.Background(), second.ID) {
		t.Fatal("an old session survived reset")
	}
}

func TestOfflineCredentialResetInvalidatesOutstandingChallenge(t *testing.T) {
	svc, adminID, secret := seededAuth(t)
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.3")
	if err != nil {
		t.Fatal(err)
	}
	offline := New(svc.store, svc.now)
	if err := offline.ResetPassword(context.Background(), adminID, "a new long passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyTOTP(context.Background(), challenge, totpCode(secret, svc.now())); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("pre-reset challenge survived offline reset: %v", err)
	}
}

func TestAuthenticationSecretsAreNotPersistedInPlaintext(t *testing.T) {
	svc := New(openTestStore(t), func() time.Time { return time.Unix(1_800_000_000, 0) })
	token, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.Tx(context.Background(), func(tx *sql.Tx) error {
		var value string
		if err := tx.QueryRow("SELECT value FROM settings WHERE key = ?", setupSettingKey).Scan(&value); err != nil {
			return err
		}
		if strings.Contains(value, token) {
			t.Fatal("plaintext setup token was persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	password := "correct horse battery staple"
	enrollment, err := svc.CompleteSetup(context.Background(), token, "admin", password)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.Tx(context.Background(), func(tx *sql.Tx) error {
		var passwordHash, totpCiphertext, recoveryHashes []byte
		if err := tx.QueryRow("SELECT password_hash, totp_secret, recovery_codes FROM admins WHERE id = 1").Scan(&passwordHash, &totpCiphertext, &recoveryHashes); err != nil {
			return err
		}
		for label, secret := range map[string]string{"password": password, "TOTP secret": enrollment.TOTPSecret, "recovery code": enrollment.RecoveryCodes[0]} {
			if bytes.Contains(passwordHash, []byte(secret)) || bytes.Contains(totpCiphertext, []byte(secret)) || bytes.Contains(recoveryHashes, []byte(secret)) {
				t.Fatalf("plaintext %s was persisted", label)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	challenge, err := svc.Authenticate(context.Background(), "admin", password, "192.0.2.30")
	if err != nil {
		t.Fatal(err)
	}
	session, err := svc.VerifyTOTP(context.Background(), challenge, enrollment.RecoveryCodes[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.Tx(context.Background(), func(tx *sql.Tx) error {
		var idHash, csrfHash []byte
		if err := tx.QueryRow("SELECT id_hash, csrf_hash FROM sessions").Scan(&idHash, &csrfHash); err != nil {
			return err
		}
		if bytes.Equal(idHash, []byte(session.ID)) || bytes.Equal(csrfHash, []byte(session.CSRFToken)) {
			t.Fatal("plaintext session credential was persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupTokenExpiresAndIsSingleUse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc := New(openTestStore(t), func() time.Time { return now })
	expired, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Minute)
	if _, err := svc.CompleteSetup(context.Background(), expired, "admin", "correct horse battery staple"); !errors.Is(err, ErrInvalidSetupToken) {
		t.Fatalf("expired token: got %v", err)
	}
	valid, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSetup(context.Background(), valid, "admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteSetup(context.Background(), valid, "admin", "correct horse battery staple"); err == nil {
		t.Fatal("setup token was reusable")
	}
}

func TestUnicodePasswordWithSpacesAuthenticates(t *testing.T) {
	svc := New(openTestStore(t), func() time.Time { return time.Unix(1_800_000_000, 0) })
	token, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	password := "ม้าสีขาว วิ่ง ช้ามาก"
	if _, err := svc.CompleteSetup(context.Background(), token, "เจ้าของ", password); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(context.Background(), "เจ้าของ", password, "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordPolicyRejectsOnlyDefinedSafetyBounds(t *testing.T) {
	for name, password := range map[string]string{
		"too short":         "short pass",
		"too long":          strings.Repeat("ก", 129),
		"common":            "password1234",
		"contains username": "safe-admin-passphrase",
	} {
		t.Run(name, func(t *testing.T) {
			svc := New(openTestStore(t), func() time.Time { return time.Unix(1_800_000_000, 0) })
			token, err := svc.CreateSetupToken(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.CompleteSetup(context.Background(), token, "admin", password); err == nil {
				t.Fatal("unsafe password was accepted")
			}
		})
	}
}

func TestTOTPAllowsOneStepSkewAndRejectsReplay(t *testing.T) {
	svc, _, secret := seededAuth(t)
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.5")
	if err != nil {
		t.Fatal(err)
	}
	code := totpCode(secret, svc.now().Add(30*time.Second))
	if _, err := svc.VerifyTOTP(context.Background(), challenge, code); err != nil {
		t.Fatalf("one-step skew rejected: %v", err)
	}
	challenge, err = svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.6")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyTOTP(context.Background(), challenge, code); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed code: got %v", err)
	}
}

func TestTOTPRejectsTwoStepSkew(t *testing.T) {
	svc, _, secret := seededAuth(t)
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyTOTP(context.Background(), challenge, totpCode(secret, svc.now().Add(-60*time.Second))); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("two-step skew: got %v", err)
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc, _, _, code := seededAuthWithRecoveryAt(t, &now)
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyTOTP(context.Background(), challenge, code); err != nil {
		t.Fatal(err)
	}
	challenge, err = svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyTOTP(context.Background(), challenge, code); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("reused recovery code: got %v", err)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		svc, _, secret := seededAuthAt(t, &now)
		session := login(t, svc, secret)
		now = now.Add(30 * time.Minute)
		if svc.SessionValid(context.Background(), session.ID) {
			t.Fatal("session survived idle expiry")
		}
	})
	t.Run("absolute", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		svc, _, secret := seededAuthAt(t, &now)
		session := login(t, svc, secret)
		for i := 0; i < 23; i++ {
			now = now.Add(29 * time.Minute)
			if !svc.SessionValid(context.Background(), session.ID) {
				t.Fatalf("session expired early after %s", now.Sub(time.Unix(1_800_000_000, 0)))
			}
		}
		now = session.AbsoluteExpiresAt
		if svc.SessionValid(context.Background(), session.ID) {
			t.Fatal("session survived absolute expiry")
		}
	})
}

func TestLoginThrottleDelayIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc, _, _ := seededAuthAt(t, &now)
	for i := 0; i < 10; i++ {
		_, _ = svc.Authenticate(context.Background(), "admin", "wrong password", "192.0.2.11")
		delay := svc.throttled([]string{"ip:192.0.2.11", accountThrottleKey("admin")})
		if delay > 8*time.Second {
			t.Fatalf("delay = %s, want at most 8s", delay)
		}
		now = now.Add(delay)
	}
}

func TestLoginThrottleStorageIsBounded(t *testing.T) {
	svc := New(openTestStore(t), func() time.Time { return time.Unix(1_800_000_000, 0) })
	for i := 0; i < maxThrottleKeys+100; i++ {
		svc.recordFailure([]string{fmt.Sprintf("ip:192.0.2.%d", i)})
	}
	if len(svc.throttles) != maxThrottleKeys {
		t.Fatalf("throttle keys = %d, want %d", len(svc.throttles), maxThrottleKeys)
	}
}

func seededAuth(t *testing.T) (*Service, int64, string) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	return seededAuthAt(t, &now)
}

func seededAuthAt(t *testing.T, now *time.Time) (*Service, int64, string) {
	t.Helper()
	svc, adminID, secret, _ := seededAuthWithRecoveryAt(t, now)
	return svc, adminID, secret
}

func seededAuthWithRecoveryAt(t *testing.T, now *time.Time) (*Service, int64, string, string) {
	t.Helper()
	svc := New(openTestStore(t), func() time.Time { return *now })
	token, err := svc.CreateSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := svc.CompleteSetup(context.Background(), token, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return svc, 1, enrollment.TOTPSecret, enrollment.RecoveryCodes[0]
}

func login(t *testing.T, svc *Service, secret string) Session {
	t.Helper()
	challenge, err := svc.Authenticate(context.Background(), "admin", "correct horse battery staple", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	code := totpCode(secret, svc.now())
	session, err := svc.VerifyTOTP(context.Background(), challenge, code)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(context.Background(), filepath.Join(dir, "tompanel.db"), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func BenchmarkPasswordHash(b *testing.B) {
	for b.Loop() {
		if _, err := hashPassword("benchmark-only long passphrase"); err != nil {
			b.Fatal(err)
		}
	}
}
