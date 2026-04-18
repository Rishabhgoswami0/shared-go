// pkg/logger/logger.go
package logger

import (
	"context"
	"os"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger interface {
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
	Fatal(msg string, fields ...zap.Field)
	With(fields ...zap.Field) Logger
	Sync() error
}

type zapLogger struct {
	internal *zap.Logger
}

func NewZapLogger(env string, meta ...zap.Field) (Logger, error) {
	var config zap.Config
	if env == "prod" {
		config = zap.NewProductionConfig()
		// Production sampling: 100 logs initial, then 100 thereafter
		config.Sampling = &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		}
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Standardize on ISO8601 for logs (required for ELK/Loki)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.OutputPaths = []string{"stdout"}

	l, err := config.Build(zap.AddCallerSkip(1))
	if err != nil {
		return nil, err
	}

	// Inject service metadata if provided
	if len(meta) > 0 {
		l = l.With(meta...)
	}

	return &zapLogger{internal: l}, nil
}

func (z *zapLogger) Debug(msg string, fields ...zap.Field) { z.internal.Debug(msg, fields...) }
func (z *zapLogger) Info(msg string, fields ...zap.Field)  { z.internal.Info(msg, fields...) }
func (z *zapLogger) Warn(msg string, fields ...zap.Field)  { z.internal.Warn(msg, fields...) }
func (z *zapLogger) Error(msg string, fields ...zap.Field) { z.internal.Error(msg, fields...) }
func (z *zapLogger) Fatal(msg string, fields ...zap.Field) { z.internal.Fatal(msg, fields...) }

func (z *zapLogger) With(fields ...zap.Field) Logger {
	return &zapLogger{internal: z.internal.With(fields...)}
}

func (z *zapLogger) Sync() error {
	return z.internal.Sync()
}

// FromContext extracts request metadata (ID, Trace, Tenant) and returns a fail-safe logger.
func FromContext(ctx context.Context) Logger {
	l := Log
	if l == nil {
		ensureLog()
		l = Log
	}

	if ctx == nil {
		return l
	}

	var fields []zap.Field
	if v := sharedctx.GetRequestID(ctx); v != "" {
		fields = append(fields, zap.String("request_id", v))
	} else {
		// Middleware Order Warning
		l.Warn("missing request_id in context - check middleware order")
	}

	if v := sharedctx.GetTraceID(ctx); v != "" {
		fields = append(fields, zap.String("trace_id", v))
	}
	if v := sharedctx.GetTenantID(ctx); v != "" {
		fields = append(fields, zap.String("tenant_id", v))
	}

	if len(fields) > 0 {
		return l.With(fields...)
	}
	return l
}

// Global logger for simple usage if needed
var Log Logger

func InitGlobal(env string, meta ...zap.Field) error {
	l, err := NewZapLogger(env, meta...)
	if err != nil {
		return err
	}
	Log = l
	return nil
}

func ensureLog() {
	if Log == nil {
		env := os.Getenv("APP_ENV")
		if env == "" {
			env = "dev"
		}
		_ = InitGlobal(env)
	}
}

func Debug(msg string, fields ...zap.Field) { ensureLog(); Log.Debug(msg, fields...) }
func Info(msg string, fields ...zap.Field)  { ensureLog(); Log.Info(msg, fields...) }
func Warn(msg string, fields ...zap.Field)  { ensureLog(); Log.Warn(msg, fields...) }
func Error(msg string, fields ...zap.Field) { ensureLog(); Log.Error(msg, fields...) }
func Fatal(msg string, fields ...zap.Field) { ensureLog(); Log.Fatal(msg, fields...) }
