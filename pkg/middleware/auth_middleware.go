package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Rishabhgoswami0/shared-go/pkg/auth"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const UserIDKey ContextKey = "userID"

// RequireAuth is an HTTP middleware function that requires a valid JWT token.
func RequireAuth(secretKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Missing or malformed Authorization header",
				})
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Validate token using auth package
			_, userID, err := auth.ValidateToken(tokenString, []byte(secretKey))
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Invalid or expired token",
				})
				return
			}

			// Inject user ID into the request's context
			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
