package logging

import (
	"context"
	"time"

	"github.com/openchami/tokensmith/pkg/errors"
	"github.com/rs/zerolog"
)

// StructuredLogger provides structured logging capabilities
type StructuredLogger struct {
	logger zerolog.Logger
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(component string) *StructuredLogger {
	return &StructuredLogger{
		logger: GetLogger(component),
	}
}

// NewStructuredLoggerFromContext creates a structured logger from context
func NewStructuredLoggerFromContext(ctx context.Context, component string) *StructuredLogger {
	return &StructuredLogger{
		logger: LoggerFromContextWithComponent(ctx, component),
	}
}

// WithField adds a field to the logger
func (l *StructuredLogger) WithField(key string, value interface{}) *StructuredLogger {
	return &StructuredLogger{
		logger: l.logger.With().Interface(key, value).Logger(),
	}
}

// WithFields adds multiple fields to the logger
func (l *StructuredLogger) WithFields(fields map[string]interface{}) *StructuredLogger {
	logger := l.logger.With()
	for key, value := range fields {
		logger = logger.Interface(key, value)
	}
	return &StructuredLogger{
		logger: logger.Logger(),
	}
}

// WithError adds an error to the logger
func (l *StructuredLogger) WithError(err error) *StructuredLogger {
	logger := l.logger.With().Err(err)

	// Add TokenSmith error details if available
	if tsErr, ok := err.(*errors.TokenSmithError); ok {
		logger = logger.
			Str("error_code", string(tsErr.Code)).
			Int("http_status", tsErr.HTTPStatus)

		if tsErr.TraceID != "" {
			logger = logger.Str("error_trace_id", tsErr.TraceID)
		}

		if tsErr.Details != nil {
			for key, value := range tsErr.Details {
				logger = logger.Interface("error_"+key, value)
			}
		}
	}

	return &StructuredLogger{
		logger: logger.Logger(),
	}
}

// WithDuration adds a duration to the logger
func (l *StructuredLogger) WithDuration(duration time.Duration) *StructuredLogger {
	return &StructuredLogger{
		logger: l.logger.With().Dur("duration", duration).Logger(),
	}
}

// Trace logs a trace message
func (l *StructuredLogger) Trace(msg string) {
	l.logger.Trace().Msg(msg)
}

// Tracef logs a formatted trace message
func (l *StructuredLogger) Tracef(format string, args ...interface{}) {
	l.logger.Trace().Msgf(format, args...)
}

// Debug logs a debug message
func (l *StructuredLogger) Debug(msg string) {
	l.logger.Debug().Msg(msg)
}

// Debugf logs a formatted debug message
func (l *StructuredLogger) Debugf(format string, args ...interface{}) {
	l.logger.Debug().Msgf(format, args...)
}

// Info logs an info message
func (l *StructuredLogger) Info(msg string) {
	l.logger.Info().Msg(msg)
}

// Infof logs a formatted info message
func (l *StructuredLogger) Infof(format string, args ...interface{}) {
	l.logger.Info().Msgf(format, args...)
}

// Warn logs a warning message
func (l *StructuredLogger) Warn(msg string) {
	l.logger.Warn().Msg(msg)
}

// Warnf logs a formatted warning message
func (l *StructuredLogger) Warnf(format string, args ...interface{}) {
	l.logger.Warn().Msgf(format, args...)
}

// Error logs an error message
func (l *StructuredLogger) Error(msg string) {
	l.logger.Error().Msg(msg)
}

// Errorf logs a formatted error message
func (l *StructuredLogger) Errorf(format string, args ...interface{}) {
	l.logger.Error().Msgf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *StructuredLogger) Fatal(msg string) {
	l.logger.Fatal().Msg(msg)
}

// Fatalf logs a formatted fatal message and exits
func (l *StructuredLogger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatal().Msgf(format, args...)
}

// Panic logs a panic message and panics
func (l *StructuredLogger) Panic(msg string) {
	l.logger.Panic().Msg(msg)
}

// Panicf logs a formatted panic message and panics
func (l *StructuredLogger) Panicf(format string, args ...interface{}) {
	l.logger.Panic().Msgf(format, args...)
}

// LogOperation logs the start and end of an operation
func (l *StructuredLogger) LogOperation(operation string, fn func() error) error {
	start := time.Now()
	l.logger.Info().Str("operation", operation).Msg("operation started")

	err := fn()

	duration := time.Since(start)
	logger := l.logger.With().
		Str("operation", operation).
		Dur("duration", duration).
		Logger()

	if err != nil {
		logger.Err(err).Msg("operation failed")
	} else {
		logger.Info().Msg("operation completed")
	}

	return err
}

// LogOperationWithResult logs the start and end of an operation with a result
func (l *StructuredLogger) LogOperationWithResult(operation string, fn func() (interface{}, error)) (interface{}, error) {
	start := time.Now()
	l.logger.Info().Str("operation", operation).Msg("operation started")

	result, err := fn()

	duration := time.Since(start)
	logger := l.logger.With().
		Str("operation", operation).
		Dur("duration", duration).
		Logger()

	if err != nil {
		logger.Err(err).Msg("operation failed")
	} else {
		logger.Info().Interface("result", result).Msg("operation completed")
	}

	return result, err
}

// LogHTTPRequest logs an HTTP request
func (l *StructuredLogger) LogHTTPRequest(method, path string, statusCode int, duration time.Duration) {
	l.logger.Info().
		Str("method", method).
		Str("path", path).
		Int("status_code", statusCode).
		Dur("duration", duration).
		Msg("http request")
}

// LogHTTPError logs an HTTP error
func (l *StructuredLogger) LogHTTPError(method, path string, statusCode int, err error, duration time.Duration) {
	l.logger.Error().
		Str("method", method).
		Str("path", path).
		Int("status_code", statusCode).
		Err(err).
		Dur("duration", duration).
		Msg("http error")
}

// LogTokenOperation logs a token-related operation
func (l *StructuredLogger) LogTokenOperation(operation, tokenType string, success bool, duration time.Duration) {
	level := l.logger.Info()
	if !success {
		level = l.logger.Error()
	}

	level.
		Str("operation", operation).
		Str("token_type", tokenType).
		Bool("success", success).
		Dur("duration", duration).
		Msg("token operation")
}

// LogPolicyOperation logs a policy-related operation
func (l *StructuredLogger) LogPolicyOperation(operation, policyType string, success bool, duration time.Duration) {
	level := l.logger.Info()
	if !success {
		level = l.logger.Error()
	}

	level.
		Str("operation", operation).
		Str("policy_type", policyType).
		Bool("success", success).
		Dur("duration", duration).
		Msg("policy operation")
}

// LogOIDCOperation logs an OIDC-related operation
func (l *StructuredLogger) LogOIDCOperation(operation, provider string, success bool, duration time.Duration) {
	level := l.logger.Info()
	if !success {
		level = l.logger.Error()
	}

	level.
		Str("operation", operation).
		Str("provider", provider).
		Bool("success", success).
		Dur("duration", duration).
		Msg("oidc operation")
}
