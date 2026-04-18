// pkg/logger/logger.go
package logger

import (
	"context"
	"os"
	"time"

	sharedctx "github.com/Rishabhgoswami0/shared-go/pkg/context"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	ServiceName          string
	Env                  string
	Version              string
	InstanceID           string
	SlowRequestThreshold time.Duration
}

var GlobalConfig Config

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
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.OutputPaths = []string{"stdout"}

	// ── 1. Create Base Console/JSON Encoder ──────────────────────────────
	var encoder zapcore.Encoder
	if env == "prod" {
		encoder = zapcore.NewJSONEncoder(config.EncoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(config.EncoderConfig)
	}

	// ── 2. Create Level-Aware Sampler Core ───────────────────────────────
	// High-scale fix: only sample INFO/DEBUG. ALWAYS log WARN/ERROR.
	baseCore := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), config.Level)
	core := baseCore

	if env == "prod" {
		sampler := zapcore.NewSamplerWithOptions(
			baseCore,
			time.Second,
			100, // Initial
			100, // Thereafter
		)
		core = &levelAwareSampler{
			Core:    baseCore,
			sampler: sampler,
		}
	}

	l := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	// ── 3. Inject Global Metadata ─────────────────────────────────────────
	// We no longer automatically inject host, relying on InitLogger config instead.
	if len(meta) > 0 {
		l = l.With(meta...)
	}

	return &zapLogger{internal: l}, nil
}

// levelAwareSampler ensures that Warn, Error, and Fatal logs are NEVER dropped by the sampler.
type levelAwareSampler struct {
	zapcore.Core
	sampler zapcore.Core
}

func (s *levelAwareSampler) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if ent.Level >= zapcore.WarnLevel {
		return s.Core.Check(ent, ce)
	}
	return s.sampler.Check(ent, ce)
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

func InitLogger(cfg Config) error {
	GlobalConfig = cfg

	// Use default threshold if not set
	if GlobalConfig.SlowRequestThreshold == 0 {
		GlobalConfig.SlowRequestThreshold = 1000 * time.Millisecond
	}

	meta := []zap.Field{
		zap.String("service", cfg.ServiceName),
		zap.String("env", cfg.Env),
		zap.String("version", cfg.Version),
		zap.String("instance_id", cfg.InstanceID),
	}
	l, err := NewZapLogger(cfg.Env, meta...)
	if err != nil {
		return err
	}
	Log = l
	return nil
}

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
