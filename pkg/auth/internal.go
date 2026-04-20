package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// GenerateInternalSignature creates an HMAC-SHA256 signature for internal service calls.
// It binds the request body and a timestamp to the secret key to prevent tampering and replays.
func GenerateInternalSignature(secret, body string, timestamp int64) string {
	payload := fmt.Sprintf("%s:%d", body, timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyInternalSignature validates an internal service call signature.
// It checks if the timestamp is within the allowed window (±60s) and if the HMAC matches.
func VerifyInternalSignature(secret, body, signature string, timestampStr string) error {
	// 1. Parse and validate timestamp
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format")
	}

	now := time.Now().Unix()
	if ts < now-60 || ts > now+60 {
		return fmt.Errorf("request timestamp expired or in the future (replay protection)")
	}

	// 2. Re-generate signature and compare
	expected := GenerateInternalSignature(secret, body, ts)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return fmt.Errorf("invalid internal signature")
	}

	return nil
}
