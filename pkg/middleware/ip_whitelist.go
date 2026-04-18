package middleware

import (
	"net"
	"net/http"
	"strings"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	SourceXForwardedFor = "x_forwarded_for"
	SourceXRealIP       = "x_real_ip"
	SourceRemoteAddr    = "remote_addr"
)

// extractHost safely strips the port from an IP address if present.
func extractHost(ip string) string {
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		return host
	}
	return ip
}

// normalizeIP removes ports and normalizes formatting. Returns "" if invalid.
func normalizeIP(ip string) string {
	ip = extractHost(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// getClientIP extracts the client IP and its source.
// Uses normalizeIP to ensure consistent format against the map logic.
func getClientIP(r *http.Request, trustProxy bool) (string, string) {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			return normalizeIP(ip), SourceXForwardedFor
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return normalizeIP(strings.TrimSpace(xri)), SourceXRealIP
		}
	}

	return normalizeIP(r.RemoteAddr), SourceRemoteAddr
}

// IPWhitelistMiddleware ensures only allowed IPs can access the API.
func IPWhitelistMiddleware(allowedIPs map[string]struct{}, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail-open if whitelist is entirely empty
			if len(allowedIPs) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ip, source := getClientIP(r, trustProxy)

			if _, allowed := allowedIPs[ip]; ip == "" || !allowed {
				ctx := r.Context()

				// Generate independent UUIDs
				reqID := uuid.New().String()
				traceID := uuid.New().String()

				// Inject strongly typed context variables before logging/response
				ctx = sharedctx.WithRequestID(ctx, reqID)
				ctx = sharedctx.WithTraceID(ctx, traceID)
				ctx = sharedctx.WithClientIP(ctx, ip)

				// Update request with new context
				r = r.WithContext(ctx)

				log := logger.FromContext(ctx)

				route := r.Pattern
				if route == "" {
					route = r.URL.Path
				}

				// Optional: get basic tenant for added audit context
				tenant := r.Header.Get("X-Tenant-ID")

				log.Warn("blocked request",
					zap.String("ip", ip),
					zap.String("ip_source", source),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.String("route", route),
					zap.Int("status", http.StatusForbidden),
					zap.String("reason", "ip_not_whitelisted"),
					zap.Bool("blocked", true),
					zap.String("tenant_id", tenant),
				)

				// Standardized RFC 7807 Response
				apperrors.WriteError(w, r, apperrors.NewForbidden(apperrors.CodeForbidden, "IP not allowed", nil))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
