package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// PanicRecovery is an HTTP middleware function that catches panics and prevents server crashes.
func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the error using the new logger.Error function
				logger.Error("Panic recovered in HTTP handler", zap.Any("error", err))

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Internal Server Error",
				})
			}
		}()

		next.ServeHTTP(w, r)
	})
}
