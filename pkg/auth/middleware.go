package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware creates a new middleware that validates JWT tokens using a JWKSClient.
func AuthMiddleware(jwksClient *JWKSClient, expectedIss string, expectedAud string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				LogEvent("jwt_validation_failed", "missing_authorization_header", nil)
				http.Error(w, "Unauthorized: missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				LogEvent("jwt_validation_failed", "invalid_authorization_format", nil)
				http.Error(w, "Unauthorized: invalid authorization format", http.StatusUnauthorized)
				return
			}
			tokenString := parts[1]

			// Fail-Closed: Parse and validate the token signature and structure
			token, err := ParseWithLeeway(tokenString, jwksClient.KeyFunc)
			if err != nil {
				LogEvent("jwt_validation_failed", "parse_or_signature_error", map[string]interface{}{"error": err.Error()})
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*CustomClaims)
			if !ok || !token.Valid {
				LogEvent("jwt_validation_failed", "invalid_claims", nil)
				http.Error(w, "Unauthorized: invalid token claims", http.StatusUnauthorized)
				return
			}

			// Validate strictly required claims (iss, aud)
			if claims.Issuer != expectedIss {
				LogEvent("jwt_validation_failed", "issuer_mismatch", map[string]interface{}{"found": claims.Issuer, "expected": expectedIss})
				http.Error(w, "Unauthorized: invalid issuer", http.StatusUnauthorized)
				return
			}

			if !audienceMatch(claims.Audience, expectedAud) {
				LogEvent("jwt_validation_failed", "audience_mismatch", map[string]interface{}{"found": claims.Audience, "expected": expectedAud})
				http.Error(w, "Unauthorized: invalid audience", http.StatusUnauthorized)
				return
			}

			// Build and inject AuthContext
			authCtx := AuthContext{
				Subject:     claims.Subject,
				TenantID:    claims.TenantID,
				Roles:       claims.Roles,
				Permissions: claims.Permissions,
				JTI:         claims.ID,
				Type:        claims.Type,
				Scope:       claims.Scope,
			}
			
			// For backward compatibility (so older things don't break instantly)
			if claims.SessionID != "" && authCtx.JTI == "" {
			    authCtx.JTI = claims.SessionID
			}

			LogEvent("token_validated_successfully", "", map[string]interface{}{
				"jti":    authCtx.JTI,
				"tenant": authCtx.TenantID,
				"sub":    authCtx.Subject,
			})

			ctx := WithAuthContext(r.Context(), authCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// audienceMatch checks if the expectedAudience is within the token's Audience array
func audienceMatch(audience jwt.ClaimStrings, expected string) bool {
	if expected == "" {
		return true // skip if not explicitly required by the service itself
	}
	for _, a := range audience {
		if a == expected {
			return true
		}
	}
	return false
}

// ExtractBearerToken is a helper for services that need to extract the raw token 
// (e.g., to forward it to another service)
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization format")
	}

	return parts[1], nil
}
