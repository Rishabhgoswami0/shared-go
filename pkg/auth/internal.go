package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// SignRaw creates a canonical HMAC-SHA256 signature for internal service calls.
func SignRaw(method, path, timestamp string, body []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(method + "\n"))
	h.Write([]byte(path + "\n"))
	h.Write([]byte(timestamp + "\n"))
	h.Write(body)
	res := hex.EncodeToString(h.Sum(nil))
	// fmt.Printf("DEBUG [SignRaw]: method=%s path=%s ts=%s bodyLen=%d sig=%s\n", method, path, timestamp, len(body), res)
	return res
}

// VerifyInternalSignature validates an internal service call signature.
func VerifyInternalSignature(signature, method, path, timestampStr string, body []byte, secret string) bool {
	// 1. Parse and validate timestamp
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	if ts < now-300 || ts > now+300 { // 5 minute window for clock skew
		return false
	}

	// 2. Re-generate signature and compare
	expected := SignRaw(method, path, timestampStr, body, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}
