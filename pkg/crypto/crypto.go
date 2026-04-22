package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// DSNPrefix is prepended to all encrypted DSN strings to identify them.
const DSNPrefix = "v1:"

// ErrInvalidCiphertext is returned when decryption fails due to tampering or a wrong key.
var ErrInvalidCiphertext = errors.New("invalid ciphertext: decryption failed (tampered data or wrong key)")

// ─── Key derivation ──────────────────────────────────────────────────────────

// deriveKey converts any string (from env var) into a fixed 32-byte AES-256 key
// using SHA-256. This lets you use a plain hex string or any passphrase as the key.
func deriveKey(rawKey string) []byte {
	hash := sha256.Sum256([]byte(rawKey))
	return hash[:]
}

// ─── EncryptDSN ──────────────────────────────────────────────────────────────

// EncryptDSN encrypts a plain-text DSN string using AES-256-GCM.
//
// Output format (base64-encoded): [ 12-byte nonce | ciphertext | 16-byte GCM tag ]
//
// The nonce is randomly generated per call, so encrypting the same DSN twice
// produces different ciphertexts — no patterns leak.
//
// encryptionKey is the raw string from your DSN_ENCRYPTION_KEY env var.
func EncryptDSN(plainDSN, encryptionKey string) (string, error) {
	if plainDSN == "" {
		return "", fmt.Errorf("EncryptDSN: plainDSN must not be empty")
	}
	if encryptionKey == "" {
		return "", fmt.Errorf("EncryptDSN: encryptionKey must not be empty")
	}

	key := deriveKey(encryptionKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("EncryptDSN: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("EncryptDSN: failed to create GCM: %w", err)
	}

	// Generate a cryptographically random 12-byte nonce (GCM standard size).
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("EncryptDSN: failed to generate nonce: %w", err)
	}

	// Seal appends: ciphertext + 16-byte GCM authentication tag
	// We prepend the nonce so Decrypt can extract it without storing it separately.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainDSN), nil)

	// Encode as base64 so it's safe to store in a TEXT column.
	b64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Prepend the version prefix so we can detect it's already encrypted
	return DSNPrefix + b64, nil
}

// ─── IsEncrypted ─────────────────────────────────────────────────────────────

// IsEncrypted returns true if the given string starts with DSNPrefix.
func IsEncrypted(dsn string) bool {
	return strings.HasPrefix(dsn, DSNPrefix)
}

// ─── DecryptDSN ──────────────────────────────────────────────────────────────

// DecryptDSN decrypts a ciphertext produced by EncryptDSN.
//
// Returns ErrInvalidCiphertext if:
//   - The ciphertext was modified (tampered data)
//   - The wrong encryption key is used
//   - The data is corrupted / too short
//
// encryptionKey must be the same value used during encryption.
func DecryptDSN(encryptedDSN, encryptionKey string) (string, error) {
	if encryptedDSN == "" {
		return "", fmt.Errorf("DecryptDSN: encryptedDSN must not be empty")
	}

	// ─── Step 1: Validate Prefix ──────────────────────────────────────────
	if !IsEncrypted(encryptedDSN) {
		return "", fmt.Errorf("DecryptDSN: text is not a valid encrypted DSN (missing prefix %q)", DSNPrefix)
	}

	// Strip the prefix before decoding base64
	cleanB64 := strings.TrimPrefix(encryptedDSN, DSNPrefix)

	if encryptionKey == "" {
		return "", fmt.Errorf("DecryptDSN: encryptionKey must not be empty")
	}

	data, err := base64.StdEncoding.DecodeString(cleanB64)
	if err != nil {
		return "", fmt.Errorf("DecryptDSN: base64 decode failed: %w", err)
	}

	key := deriveKey(encryptionKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("DecryptDSN: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("DecryptDSN: failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize() // 12 bytes
	if len(data) < nonceSize+gcm.Overhead() {
		return "", ErrInvalidCiphertext
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Open authenticates AND decrypts. If the GCM tag doesn't match → error.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Don't leak internal error — could reveal oracle information.
		return "", ErrInvalidCiphertext
	}

	return string(plaintext), nil
}

// RandomInt generates a cryptographically secure random integer in the range [0, max).
func RandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("RandomInt: max must be positive")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
