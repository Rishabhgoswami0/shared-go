// pkg/logger/logger.go
package logger

import (
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

func NewZapLogger(env string) (Logger, error) {
	var config zap.Config
	if env == "prod" {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	config.OutputPaths = []string{"stdout"}

	l, err := config.Build(zap.AddCallerSkip(1))
	if err != nil {
		return nil, err
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

// Global logger for simple usage if needed
var Log Logger

func InitGlobal(env string) error {
	l, err := NewZapLogger(env)
	if err != nil {
		return err
	}
	Log = l
	return nil
}
