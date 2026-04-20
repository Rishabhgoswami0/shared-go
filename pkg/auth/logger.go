package auth

import (
	"github.com/Rishabhgoswami0/shared-go/pkg/logger"
	"go.uber.org/zap"
)

// LogEvent prints a standardized structured log for auth events using the global logger.
func LogEvent(event string, reason string, details map[string]interface{}) {
	fields := []zap.Field{
		zap.String("event", event),
	}

	if reason != "" {
		fields = append(fields, zap.String("reason", reason))
	}

	if len(details) > 0 {
		fields = append(fields, zap.Any("details", details))
	}

	// Logging as INFO by default for auth events (e.g. login success/attempts).
	// For actual errors, the caller should generally use logger.Error directly.
	logger.Info("auth event", fields...)
}
