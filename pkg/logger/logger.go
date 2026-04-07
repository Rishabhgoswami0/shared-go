// pkg/logger/logger.go
package logger

type Logger interface {
	Info(msg string)
	Error(msg string)
}
