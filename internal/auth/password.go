package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemoryKiB   = 64 * 1024
	argonIterations  = 2
	argonParallelism = 2
	argonSaltBytes   = 16
	argonKeyBytes    = 32
)

var commonPasswords = map[string]struct{}{
	"123456789012": {}, "adminadminadmin": {}, "iloveyou12345": {},
	"letmeinletmein": {}, "password1234": {}, "qwertyqwerty": {},
	"welcome12345": {},
}

func validatePassword(password, username string) error {
	if !utf8.ValidString(password) {
		return errors.New("password must be valid UTF-8")
	}
	length := utf8.RuneCountInString(password)
	if length < 12 || length > 128 {
		return errors.New("password must be 12-128 characters")
	}
	lower := strings.ToLower(password)
	if _, found := commonPasswords[lower]; found {
		return errors.New("password is too common")
	}
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return errors.New("password must not contain the username")
	}
	return nil
}

func hashPassword(password string) ([]byte, error) {
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
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
