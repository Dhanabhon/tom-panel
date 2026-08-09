package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return aead, nil
}

// Encrypt seals plain with a random nonce and field-specific authenticated data.
func (s *Store) Encrypt(plain, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, fmt.Errorf("encrypt: field AAD is required")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("encrypt: generate nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plain, aad), nil
}

// Decrypt opens ciphertext only when its field-specific authenticated data matches.
func (s *Store) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, fmt.Errorf("decrypt: field AAD is required")
	}
	nonceSize := s.aead.NonceSize()
	if len(ciphertext) < nonceSize+s.aead.Overhead() {
		return nil, fmt.Errorf("decrypt: malformed ciphertext")
	}
	plain, err := s.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authenticate ciphertext: %w", err)
	}
	return plain, nil
}
