package auth

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func TestVerifyEntitlementsSignature(t *testing.T) {
	secret := "test-secret"
	gatewayID := "gw-prod-01"
	whitelisted := []string{"gw-prod-01", "gw-prod-02"}

	now := time.Now().Unix()
	ctx := EntitlementContext{
		TenantID:           "test-tenant-id",
		Service:            "PROPERTY-TAX",
		Capabilities:       []string{"PROPERTY-TAX:PROPERTY_TAX.READ", "PROPERTY-TAX:PROPERTY_TAX.WRITE"},
		EntitlementVersion: 1,
		LifecycleState:     "ACTIVE",
		IssuedAt:           now,
		ExpiresAt:          now + 300, // 5 min TTL
	}

	ctxJSON, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("failed to marshal context: %v", err)
	}
	base64Payload := base64.StdEncoding.EncodeToString(ctxJSON)

	method := "GET"
	path := "/api/v1/properties"
	timestampStr := strconv.FormatInt(now, 10)
	requestID := "req-nonce-123"

	// Sign payload
	sig := SignEntitlements(method, path, timestampStr, requestID, gatewayID, base64Payload, secret)

	t.Run("Valid Signature", func(t *testing.T) {
		valid, reason, gotCtx := VerifyEntitlementsSignature(sig, method, path, timestampStr, requestID, gatewayID, base64Payload, secret, whitelisted, 5*time.Minute)
		if !valid {
			t.Errorf("expected valid signature, got invalid with reason: %s", reason)
		}
		if gotCtx == nil || gotCtx.TenantID != ctx.TenantID {
			t.Errorf("expected context match, got %+v", gotCtx)
		}
	})

	t.Run("Gateway Whitelist Rejection", func(t *testing.T) {
		valid, reason, _ := VerifyEntitlementsSignature(sig, method, path, timestampStr, requestID, "unauthorized-gw", base64Payload, secret, whitelisted, 5*time.Minute)
		if valid {
			t.Error("expected invalid for un-whitelisted gateway")
		}
		if reason != "gateway_not_whitelisted" {
			t.Errorf("expected gateway_not_whitelisted, got: %s", reason)
		}
	})

	t.Run("Clock Skew Rejection", func(t *testing.T) {
		oldTimestampStr := strconv.FormatInt(now-600, 10) // 10 minutes ago
		oldSig := SignEntitlements(method, path, oldTimestampStr, requestID, gatewayID, base64Payload, secret)

		valid, reason, _ := VerifyEntitlementsSignature(oldSig, method, path, oldTimestampStr, requestID, gatewayID, base64Payload, secret, whitelisted, 5*time.Minute)
		if valid {
			t.Error("expected invalid signature due to clock skew")
		}
		if reason != "timestamp_clock_skew" {
			t.Errorf("expected timestamp_clock_skew, got: %s", reason)
		}
	})

	t.Run("Signature Mismatch", func(t *testing.T) {
		valid, reason, _ := VerifyEntitlementsSignature(sig, method, path, timestampStr, requestID, gatewayID, base64Payload, "wrong-secret", whitelisted, 5*time.Minute)
		if valid {
			t.Error("expected signature mismatch with wrong secret")
		}
		if reason != "signature_mismatch" {
			t.Errorf("expected signature_mismatch, got: %s", reason)
		}
	})

	t.Run("Expired Payload Rejection", func(t *testing.T) {
		expiredCtx := ctx
		expiredCtx.ExpiresAt = now - 10 // Expired 10s ago
		expiredJSON, _ := json.Marshal(expiredCtx)
		expiredBase64 := base64.StdEncoding.EncodeToString(expiredJSON)
		expiredSig := SignEntitlements(method, path, timestampStr, requestID, gatewayID, expiredBase64, secret)

		valid, reason, _ := VerifyEntitlementsSignature(expiredSig, method, path, timestampStr, requestID, gatewayID, expiredBase64, secret, whitelisted, 5*time.Minute)
		if valid {
			t.Error("expected expired payload to be rejected")
		}
		if reason != "payload_expired" {
			t.Errorf("expected payload_expired, got: %s", reason)
		}
	})
}
