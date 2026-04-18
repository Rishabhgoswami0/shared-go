package middleware

import (
	"net/http"
	"sync"
	"time"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	RPS             int
	Burst           int
	CleanupInterval time.Duration
	TTL             time.Duration
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiter struct {
	clients    map[string]*clientLimiter
	mu         sync.Mutex
	cfg        RateLimitConfig
	trustProxy bool
}

// NewRateLimiter creates a new rate limiter scoped to its own instance state.
func NewRateLimiter(cfg RateLimitConfig, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		clients:    make(map[string]*clientLimiter),
		cfg:        cfg,
		trustProxy: trustProxy,
	}

	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) buildClientKey(r *http.Request) string {
	ip, _ := GetClientIP(r, rl.trustProxy)
	tenant := r.Header.Get("X-Tenant-ID")

	if ip == "" {
		return ""
	}

	if tenant != "" {
		return tenant + ":" + ip
	}
	return ip
}

// Middleware returns the HTTP handler implementing rate limiting.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail-open if RPS is disabled
			if rl.cfg.RPS <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			key := rl.buildClientKey(r)
			if key == "" {
				// Safety fallback if key building completely fails
				next.ServeHTTP(w, r)
				return
			}

			rl.mu.Lock()
			cl, exists := rl.clients[key]
			if !exists {
				cl = &clientLimiter{
					limiter: rate.NewLimiter(rate.Limit(rl.cfg.RPS), rl.cfg.Burst),
				}
				rl.clients[key] = cl
			}
			cl.lastSeen = time.Now()
			rl.mu.Unlock()

			if !cl.limiter.Allow() {
				rl.handleLimitExceeded(w, r, key)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) handleLimitExceeded(w http.ResponseWriter, r *http.Request, key string) {
	// Generate IDs
	reqID := uuid.New().String()
	traceID := uuid.New().String()

	// Inject Context 
	ctx := r.Context()
	ctx = sharedctx.WithRequestID(ctx, reqID)
	ctx = sharedctx.WithTraceID(ctx, traceID)

	// Inject IP via shared utility
	ip, source := GetClientIP(r, rl.trustProxy)
	ctx = sharedctx.WithClientIP(ctx, ip)

	// Update Request Context
	r = r.WithContext(ctx)

	// Load standard logger
	log := logger.FromContext(ctx)

	route := r.Pattern
	if route == "" {
		route = r.URL.Path
	}

	tenant := r.Header.Get("X-Tenant-ID")

	log.Warn("rate limit exceeded",
		zap.String("client_key", key),
		zap.String("ip", ip),
		zap.String("ip_source", source),
		zap.String("tenant_id", tenant),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("route", route),
		zap.Int("status", http.StatusTooManyRequests),
		zap.String("status_class", "4xx"),
		zap.String("reason", "rate_limit_exceeded"),
		zap.Bool("blocked", true),
	)

	// Standards compliant response
	w.Header().Set("Retry-After", "1")
	err := apperrors.NewTooManyRequests(apperrors.CodeTooManyRequests, "Too many requests. Please try again later.", nil, "1")
	apperrors.WriteError(w, r, err)
}

func (rl *RateLimiter) cleanup() {
	if rl.cfg.TTL <= 0 {
		return
	}

	ticker := time.NewTicker(rl.cfg.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for key, cl := range rl.clients {
			if time.Since(cl.lastSeen) > rl.cfg.TTL {
				delete(rl.clients, key)
			}
		}
		rl.mu.Unlock()
	}
}
