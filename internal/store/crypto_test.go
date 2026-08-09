package store

import (
	"bytes"
	"testing"
)

func TestCiphertextCannotMoveBetweenFields(t *testing.T) {
	s := openTestStore(t)
	blob, err := s.Encrypt([]byte("token"), []byte("integrations:1:token"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decrypt(blob, []byte("admins:1:secret")); err == nil {
		t.Fatal("AAD mismatch accepted")
	}
}

func TestEncryptRoundTripUsesRandomNonces(t *testing.T) {
	s := openTestStore(t)
	plain := []byte("token")
	aad := []byte("integrations:1:token")
	first, err := s.Encrypt(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Encrypt(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("identical plaintext produced identical ciphertext")
	}
	got, err := s.Decrypt(first, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Decrypt() = %q, want %q", got, plain)
	}
}

func TestDecryptRejectsMalformedCiphertext(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Decrypt([]byte("short"), []byte("integrations:1:token")); err == nil {
		t.Fatal("malformed ciphertext accepted")
	}
}

func TestEncryptionRequiresFieldAAD(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Encrypt([]byte("token"), nil); err == nil {
		t.Fatal("empty AAD accepted")
	}
}
