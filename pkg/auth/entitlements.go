package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// EntitlementContext represents the structured context resolved by the API Gateway and verified downstream.
type EntitlementContext struct {
	TenantID           string   `json:"tenant_id"`
	Service            string   `json:"service"`
	Capabilities       []string `json:"capabilities"`
	EntitlementVersion int      `json:"entitlement_version"`
	LifecycleState     string   `json:"lifecycle_state"`
	IssuedAt           int64    `json:"issued_at"`
	ExpiresAt          int64    `json:"expires_at"`
}

// SignEntitlements creates a canonical HMAC-SHA256 signature for internal entitlement propagation.
func SignEntitlements(method, path, timestamp, requestID, gatewayID, base64Payload, secret string) string {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		path,
		timestamp,
		requestID,
		gatewayID,
		base64Payload,
	)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyEntitlementsSignature validates the incoming request's signature, timestamp, expiration, and gateway whitelisting.
func VerifyEntitlementsSignature(sig, method, path, timestampStr, requestID, gatewayID, base64Payload, secret string, whitelistedGateways []string, maxClockSkew time.Duration) (bool, string, *EntitlementContext) {
	// 1. Check Gateway Whitelist
	isWhitelisted := false
	for _, gw := range whitelistedGateways {
		if gw == gatewayID && gatewayID != "" {
			isWhitelisted = true
			break
		}
	}
	if !isWhitelisted {
		return false, "gateway_not_whitelisted", nil
	}

	// 2. Parse and validate timestamp (clock skew check)
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, "invalid_timestamp", nil
	}

	now := time.Now().Unix()
	skew := int64(maxClockSkew.Seconds())
	if ts < now-skew || ts > now+skew {
		return false, "timestamp_clock_skew", nil
	}

	// 3. Re-generate signature and compare
	expected := SignEntitlements(method, path, timestampStr, requestID, gatewayID, base64Payload, secret)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false, "signature_mismatch", nil
	}

	// 4. Decode payload to check expiration
	payloadBytes, err := base64.StdEncoding.DecodeString(base64Payload)
	if err != nil {
		return false, "invalid_base64_payload", nil
	}

	var ctx EntitlementContext
	if err := json.Unmarshal(payloadBytes, &ctx); err != nil {
		return false, "payload_json_unmarshal_failed", nil
	}

	if now > ctx.ExpiresAt {
		return false, "payload_expired", nil
	}

	return true, "", &ctx
}
