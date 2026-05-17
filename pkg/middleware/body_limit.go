package middleware

import (
	"net/http"
)

// BodyLimiter returns a middleware that enforces request body size limits.
// It uses defaultLimit unless the request path matches an entry in the overrides map.
func BodyLimiter(defaultLimit int64, overrides map[string]int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := defaultLimit
			// Check for exact match or prefix match in overrides
			for path, customLimit := range overrides {
				if r.URL.Path == path || (len(path) > 0 && path[len(path)-1] == '/' && len(r.URL.Path) >= len(path) && r.URL.Path[:len(path)] == path) {
					limit = customLimit
					break
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
