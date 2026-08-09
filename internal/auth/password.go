package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemoryKiB         = 64 * 1024
	argonIterations        = 2
	argonParallelism       = 2
	argonSaltBytes         = 16
	argonKeyBytes          = 32
	maxConcurrentArgonWork = 2
)

var argonWorkGate = make(chan struct{}, maxConcurrentArgonWork)

//go:embed common-passwords.txt
var commonPasswordData string

var commonPasswords = loadCommonPasswords()

func validatePassword(password, username string) error {
	if !utf8.ValidString(password) {
		return errors.New("password must be valid UTF-8")
	}
	length := utf8.RuneCountInString(password)
	if length < 12 || length > 128 {
		return errors.New("password must be 12-128 characters")
	}
	lower := strings.ToLower(password)
	if _, found := commonPasswords[normalizeCommonPassword(password)]; found {
		return errors.New("password is too common")
	}
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return errors.New("password must not contain the username")
	}
	return nil
}

func loadCommonPasswords() map[string]struct{} {
	passwords := make(map[string]struct{}, 10_000)
	for _, password := range strings.Split(commonPasswordData, "\n") {
		password = strings.TrimSpace(password)
		if password == "" || strings.HasPrefix(password, "#") {
			continue
		}
		passwords[normalizeCommonPassword(password)] = struct{}{}
	}
	return passwords
}

func normalizeCommonPassword(password string) string {
	var normalized strings.Builder
	normalized.Grow(len(password))
	for _, r := range strings.ToLower(password) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}
	return normalized.String()
}

func acquireArgonWork(ctx context.Context) error {
	select {
	case argonWorkGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseArgonWork() { <-argonWorkGate }

func hashPassword(ctx context.Context, password string) ([]byte, error) {
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	if err := acquireArgonWork(ctx); err != nil {
		return nil, err
	}
	defer releaseArgonWork()
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemoryKiB, argonParallelism, argonKeyBytes)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	clearBytes(key)
	return []byte(encoded), nil
}

func passwordMatches(encoded []byte, password string) bool {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil ||
		memory == 0 || memory > argonMemoryKiB || iterations == 0 || iterations > 10 || parallelism == 0 || parallelism > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != argonKeyBytes {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want)))
	defer clearBytes(got)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
