package logger

import (
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log is a globally accessible Zap logger.
var Log *zap.Logger

// InitLogger initializes a production Zap logger with ISO8601 time formatting.
func InitLogger() {
	config := zap.NewProductionConfig()
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := config.Build()
	if err != nil {
		log.Fatalf("Failed to initialize zap logger: %v", err)
	}

	Log = logger
}

// Info logs a message at InfoLevel with optional fields.
func Info(msg string, fields ...zap.Field) {
	if Log == nil {
		InitLogger()
	}
	Log.Info(msg, fields...)
}

// Error logs a message at ErrorLevel with optional fields.
func Error(msg string, fields ...zap.Field) {
	if Log == nil {
		InitLogger()
	}
	Log.Error(msg, fields...)
}
