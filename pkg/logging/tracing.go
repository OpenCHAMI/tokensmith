package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TraceIDKey is the context key for trace ID
type TraceIDKey struct{}

// CorrelationIDKey is the context key for correlation ID
type CorrelationIDKey struct{}

// UserIDKey is the context key for user ID
type UserIDKey struct{}

// RequestIDKey is the context key for request ID
type RequestIDKey struct{}

// GenerateTraceID generates a random trace ID
func GenerateTraceID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateCorrelationID generates a random correlation ID
func GenerateCorrelationID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// WithTraceID adds a trace ID to the context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey{}, traceID)
}

// WithCorrelationID adds a correlation ID to the context
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, CorrelationIDKey{}, correlationID)
}

// WithUserID adds a user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey{}, userID)
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey{}, requestID)
}

// GetTraceID extracts the trace ID from the context
func GetTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value(TraceIDKey{}).(string); ok {
		return traceID
	}
	return ""
}

// GetCorrelationID extracts the correlation ID from the context
func GetCorrelationID(ctx context.Context) string {
	if correlationID, ok := ctx.Value(CorrelationIDKey{}).(string); ok {
		return correlationID
	}
	return ""
}

// GetUserID extracts the user ID from the context
func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(UserIDKey{}).(string); ok {
		return userID
	}
	return ""
}

// GetRequestID extracts the request ID from the context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return requestID
	}
	return ""
}

// LoggerFromContext returns a logger with tracing information from the context
func LoggerFromContext(ctx context.Context) zerolog.Logger {
	logger := log.Logger

	if traceID := GetTraceID(ctx); traceID != "" {
		logger = logger.With().Str("trace_id", traceID).Logger()
	}

	if correlationID := GetCorrelationID(ctx); correlationID != "" {
		logger = logger.With().Str("correlation_id", correlationID).Logger()
	}

	if userID := GetUserID(ctx); userID != "" {
		logger = logger.With().Str("user_id", userID).Logger()
	}

	if requestID := GetRequestID(ctx); requestID != "" {
		logger = logger.With().Str("request_id", requestID).Logger()
	}

	return logger
}

// LoggerFromContextWithComponent returns a logger with tracing information and component
func LoggerFromContextWithComponent(ctx context.Context, component string) zerolog.Logger {
	return LoggerFromContext(ctx).With().Str("component", component).Logger()
}

// ExtractTraceInfoFromRequest extracts tracing information from HTTP headers
func ExtractTraceInfoFromRequest(r *http.Request) (traceID, correlationID string) {
	// Check for standard tracing headers
	traceID = r.Header.Get("X-Trace-ID")
	if traceID == "" {
		traceID = r.Header.Get("X-Request-ID")
	}
	if traceID == "" {
		traceID = r.Header.Get("X-Correlation-ID")
	}

	correlationID = r.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = r.Header.Get("X-Request-ID")
	}

	// Generate new IDs if not present
	if traceID == "" {
		traceID = GenerateTraceID()
	}
	if correlationID == "" {
		correlationID = GenerateCorrelationID()
	}

	return traceID, correlationID
}

// ContextFromRequest creates a context with tracing information from an HTTP request
func ContextFromRequest(r *http.Request) context.Context {
	ctx := r.Context()

	traceID, correlationID := ExtractTraceInfoFromRequest(r)
	ctx = WithTraceID(ctx, traceID)
	ctx = WithCorrelationID(ctx, correlationID)

	// Extract user ID from Authorization header if present
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		// This is a simple extraction - in practice you'd parse the token
		// For now, we'll just use the first part of the token as a user identifier
		parts := strings.Split(authHeader, " ")
		if len(parts) >= 2 {
			token := parts[1]
			if len(token) > 8 {
				userID := token[:8] // Use first 8 characters as user identifier
				ctx = WithUserID(ctx, userID)
			}
		}
	}

	return ctx
}

// Middleware creates a middleware that adds tracing to requests
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create context with tracing information
		ctx := ContextFromRequest(r)

		// Add tracing headers to response
		traceID := GetTraceID(ctx)
		correlationID := GetCorrelationID(ctx)

		if traceID != "" {
			w.Header().Set("X-Trace-ID", traceID)
		}
		if correlationID != "" {
			w.Header().Set("X-Correlation-ID", correlationID)
		}

		// Create logger with tracing context
		logger := LoggerFromContextWithComponent(ctx, "http")
		logger.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Str("user_agent", r.UserAgent()).
			Msg("request started")

		// Continue with the request
		next.ServeHTTP(w, r.WithContext(ctx))

		logger.Info().Msg("request completed")
	})
}
