package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// LimiterBackend defines the interface for distributed or local rate limiting backends.
type LimiterBackend interface {
	// Allow checks if a request for the given key is permitted.
	// Returns true if allowed, or false with an optional error if denied or backend failed.
	Allow(ctx context.Context, key string, rps, burst int) (bool, error)
}

// RateLimitConfig defines the global operational parameters for rate limiting.
type RateLimitConfig struct {
	Enabled    bool
	RPS        int
	Burst      int
	SkipPaths  []string
	TrustProxy bool
}

// RateLimiter is a high-level middleware that orchestrates rate limiting logic across backends.
type RateLimiter struct {
	backend LimiterBackend
	cfg     RateLimitConfig
}

// NewRateLimiter creates a new orchestrator with a specific backend (e.g. Redis with Memory fallback).
func NewRateLimiter(cfg RateLimitConfig, backend LimiterBackend) *RateLimiter {
	return &RateLimiter{
		cfg:     cfg,
		backend: backend,
	}
}

// Middleware returns the HTTP handler implementing the rate limiting chain.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Feature Toggle & Skip Paths
			if !rl.cfg.Enabled || rl.isSkipped(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// 2. Build Client Key (Key Strategy: Authenticated vs Public)
			key := rl.buildClientKey(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			// 3. Backend Check
			allowed, err := rl.backend.Allow(r.Context(), key, rl.cfg.RPS, rl.cfg.Burst)
			if err != nil {
				// FAIL-OPEN: If backend fails, log and allow request to prevent downtime.
				logger.FromContext(r.Context()).Error("rate_limiter: backend error, failing open", zap.Error(err), zap.String("key", key))
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				rl.handleLimitExceeded(w, r, key)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) buildClientKey(r *http.Request) string {
	ip, _ := GetClientIP(r, rl.cfg.TrustProxy)

	// Check if authenticated (Request context should have userID if AuthMiddleware ran before,
	// but normally RateLimiter runs AFTER RequestID but BEFORE Auth in the gateway.
	// In some designs it might run after Auth.
	// For Auth-Service specifically, it runs before handler but after RequestID/Logging).

	// Stable vFinal Strategy: /login -> IP, authenticated -> user:IP
	userID := sharedctx.GetUserID(r.Context())
	if userID != "" {
		return fmt.Sprintf("%s:%s", userID, ip)
	}

	return ip
}

func (rl *RateLimiter) isSkipped(path string) bool {
	for _, skip := range rl.cfg.SkipPaths {
		if strings.HasPrefix(path, skip) {
			return true
		}
	}
	return false
}

func (rl *RateLimiter) handleLimitExceeded(w http.ResponseWriter, r *http.Request, key string) {
	ctx := r.Context()
	log := logger.FromContext(ctx)

	// Standards-compliant header (Static 1s for now, can be enhanced with dynamic refill time)
	w.Header().Set("Retry-After", "1")

	log.Warn("rate limit exceeded",
		zap.String("client_key", key),
		zap.String("path", r.URL.Path),
		zap.Int("status", http.StatusTooManyRequests),
		zap.String("reason", "rate_limit_exceeded"),
	)

	// RFC 7807 Response
	appErr := apperrors.NewTooManyRequests(
		apperrors.CodeTooManyRequests,
		"Too many requests. Please try again later.",
		nil,
		"1",
	)
	apperrors.WriteError(w, r, appErr)
}
