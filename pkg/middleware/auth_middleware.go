package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Rishabhgoswami0/shared-go/pkg/auth"
	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
)

// ContextKey is a custom type for request-scoped context keys to avoid collisions.
type ContextKey string

const UserIDKey ContextKey = "userID"

// RequireAuth is an HTTP middleware that validates a JWT Bearer token.
// On failure it responds with an RFC 7807 401 Unauthorized via WriteError.
func RequireAuth(secretKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				apperrors.WriteError(w, r, apperrors.NewUnauthorized(
					"MISSING_TOKEN",
					"missing or malformed Authorization header",
					nil,
				))
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			_, userID, err := auth.ValidateToken(tokenString, []byte(secretKey))
			if err != nil {
				apperrors.WriteError(w, r, apperrors.NewUnauthorized(
					"INVALID_TOKEN",
					"invalid or expired token",
					err,
				))
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
