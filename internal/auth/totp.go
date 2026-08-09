package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30 * time.Second
	totpSkew   = int64(1)
)

func newTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	defer clearBytes(secret)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func totpURI(username, secret string) string {
	query := url.Values{"secret": {secret}, "issuer": {"TomPanel"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("TomPanel:"+username) + "?" + query.Encode()
}

func totpCode(secret string, at time.Time) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	defer clearBytes(raw)
	return hotp(raw, uint64(at.Unix()/int64(totpPeriod/time.Second)))
}

func matchingTOTPCounter(secret, code string, at time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	defer clearBytes(raw)
	current := at.Unix() / int64(totpPeriod/time.Second)
	for offset := -totpSkew; offset <= totpSkew; offset++ {
		counter := current + offset
		if counter >= 0 && subtle.ConstantTimeCompare([]byte(hotp(raw, uint64(counter))), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

func hotp(secret []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", value)
}

func newRecoveryCodes() ([]string, [][]byte, error) {
	codes := make([]string, 10)
	hashes := make([][]byte, 10)
	for i := range codes {
		random := make([]byte, 10)
		if _, err := rand.Read(random); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random)
		codes[i] = encoded[:8] + "-" + encoded[8:]
		digest := recoveryCodeHash(codes[i])
		hashes[i] = digest[:]
		clearBytes(random)
	}
	return codes, hashes, nil
}

func recoveryCodeHash(code string) [sha256.Size]byte {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	return sha256.Sum256([]byte(normalized))
}

func encodeRecoveryHashes(hashes [][]byte) []byte {
	parts := make([]string, len(hashes))
	for i, hash := range hashes {
		parts[i] = base64.RawStdEncoding.EncodeToString(hash)
	}
	return []byte(strings.Join(parts, ","))
}

func consumeRecoveryCode(encoded []byte, code string) ([]byte, bool) {
	got := recoveryCodeHash(code)
	parts := strings.Split(string(encoded), ",")
	kept := make([]string, 0, len(parts))
	found := false
	for _, part := range parts {
		want, err := base64.RawStdEncoding.DecodeString(part)
		match := err == nil && len(want) == sha256.Size && subtle.ConstantTimeCompare(got[:], want) == 1
		if match && !found {
			found = true
			continue
		}
		if part != "" {
			kept = append(kept, part)
		}
	}
	return []byte(strings.Join(kept, ",")), found
}
