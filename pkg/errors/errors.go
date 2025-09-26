package errors

import (
	"fmt"
	"net/http"
)

// ErrorCode represents a standardized error code
type ErrorCode string

const (
	// Authentication and Authorization errors
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden          ErrorCode = "FORBIDDEN"
	ErrCodeInvalidToken       ErrorCode = "INVALID_TOKEN"
	ErrCodeTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenMalformed     ErrorCode = "TOKEN_MALFORMED"
	ErrCodeInsufficientScope  ErrorCode = "INSUFFICIENT_SCOPE"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"

	// Configuration errors
	ErrCodeInvalidConfig     ErrorCode = "INVALID_CONFIG"
	ErrCodeMissingConfig     ErrorCode = "MISSING_CONFIG"
	ErrCodeConfigValidation  ErrorCode = "CONFIG_VALIDATION"
	ErrCodeUnsupportedConfig ErrorCode = "UNSUPPORTED_CONFIG"

	// Policy errors
	ErrCodePolicyEvaluation ErrorCode = "POLICY_EVALUATION"
	ErrCodePolicyValidation ErrorCode = "POLICY_VALIDATION"
	ErrCodePolicyNotFound   ErrorCode = "POLICY_NOT_FOUND"
	ErrCodeInvalidPolicy    ErrorCode = "INVALID_POLICY"

	// OIDC Provider errors
	ErrCodeProviderUnavailable ErrorCode = "PROVIDER_UNAVAILABLE"
	ErrCodeProviderTimeout     ErrorCode = "PROVIDER_TIMEOUT"
	ErrCodeProviderError       ErrorCode = "PROVIDER_ERROR"
	ErrCodeIntrospectionFailed ErrorCode = "INTROSPECTION_FAILED"
	ErrCodeJWKSUnavailable     ErrorCode = "JWKS_UNAVAILABLE"

	// Token Service errors
	ErrCodeTokenGeneration ErrorCode = "TOKEN_GENERATION"
	ErrCodeTokenValidation ErrorCode = "TOKEN_VALIDATION"
	ErrCodeTokenExchange   ErrorCode = "TOKEN_EXCHANGE"
	ErrCodeServiceAuth     ErrorCode = "SERVICE_AUTH"

	// Internal errors
	ErrCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrCodeNotImplemented     ErrorCode = "NOT_IMPLEMENTED"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"
	ErrCodeRateLimited        ErrorCode = "RATE_LIMITED"

	// Validation errors
	ErrCodeValidation      ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput    ErrorCode = "INVALID_INPUT"
	ErrCodeMissingRequired ErrorCode = "MISSING_REQUIRED"
	ErrCodeInvalidFormat   ErrorCode = "INVALID_FORMAT"
)

// TokenSmithError represents a standardized error with context
type TokenSmithError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Cause      error                  `json:"cause,omitempty"`
	HTTPStatus int                    `json:"http_status"`
	TraceID    string                 `json:"trace_id,omitempty"`
}

// Error implements the error interface
func (e *TokenSmithError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error
func (e *TokenSmithError) Unwrap() error {
	return e.Cause
}

// WithDetails adds additional context to the error
func (e *TokenSmithError) WithDetails(key string, value interface{}) *TokenSmithError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithTraceID adds a trace ID to the error
func (e *TokenSmithError) WithTraceID(traceID string) *TokenSmithError {
	e.TraceID = traceID
	return e
}

// New creates a new TokenSmithError with the given code and message
func New(code ErrorCode, message string) *TokenSmithError {
	return &TokenSmithError{
		Code:       code,
		Message:    message,
		HTTPStatus: getHTTPStatus(code),
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code ErrorCode, message string) *TokenSmithError {
	return &TokenSmithError{
		Code:       code,
		Message:    message,
		Cause:      err,
		HTTPStatus: getHTTPStatus(code),
	}
}

// Wrapf wraps an existing error with formatted message
func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *TokenSmithError {
	return &TokenSmithError{
		Code:       code,
		Message:    fmt.Sprintf(format, args...),
		Cause:      err,
		HTTPStatus: getHTTPStatus(code),
	}
}

// getHTTPStatus returns the appropriate HTTP status code for an error code
func getHTTPStatus(code ErrorCode) int {
	switch code {
	case ErrCodeUnauthorized, ErrCodeInvalidToken, ErrCodeTokenExpired, ErrCodeTokenMalformed, ErrCodeInvalidCredentials:
		return http.StatusUnauthorized
	case ErrCodeForbidden, ErrCodeInsufficientScope:
		return http.StatusForbidden
	case ErrCodeInvalidConfig, ErrCodeMissingConfig, ErrCodeConfigValidation, ErrCodeUnsupportedConfig,
		ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingRequired, ErrCodeInvalidFormat:
		return http.StatusBadRequest
	case ErrCodeProviderUnavailable, ErrCodeProviderTimeout, ErrCodeProviderError, ErrCodeIntrospectionFailed, ErrCodeJWKSUnavailable,
		ErrCodeServiceUnavailable:
		return http.StatusServiceUnavailable
	case ErrCodeTimeout:
		return http.StatusRequestTimeout
	case ErrCodeRateLimited:
		return http.StatusTooManyRequests
	case ErrCodeNotImplemented:
		return http.StatusNotImplemented
	case ErrCodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// IsTokenSmithError checks if an error is a TokenSmithError
func IsTokenSmithError(err error) bool {
	_, ok := err.(*TokenSmithError)
	return ok
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) ErrorCode {
	if tsErr, ok := err.(*TokenSmithError); ok {
		return tsErr.Code
	}
	return ErrCodeInternal
}

// GetHTTPStatus extracts the HTTP status from an error
func GetHTTPStatus(err error) int {
	if tsErr, ok := err.(*TokenSmithError); ok {
		return tsErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

// GetTraceID extracts the trace ID from an error
func GetTraceID(err error) string {
	if tsErr, ok := err.(*TokenSmithError); ok {
		return tsErr.TraceID
	}
	return ""
}

// Common error constructors for frequently used errors

// NewUnauthorized creates an unauthorized error
func NewUnauthorized(message string) *TokenSmithError {
	return New(ErrCodeUnauthorized, message)
}

// NewForbidden creates a forbidden error
func NewForbidden(message string) *TokenSmithError {
	return New(ErrCodeForbidden, message)
}

// NewInvalidToken creates an invalid token error
func NewInvalidToken(message string) *TokenSmithError {
	return New(ErrCodeInvalidToken, message)
}

// NewTokenExpired creates a token expired error
func NewTokenExpired(message string) *TokenSmithError {
	return New(ErrCodeTokenExpired, message)
}

// NewInsufficientScope creates an insufficient scope error
func NewInsufficientScope(message string) *TokenSmithError {
	return New(ErrCodeInsufficientScope, message)
}

// NewInvalidConfig creates an invalid config error
func NewInvalidConfig(message string) *TokenSmithError {
	return New(ErrCodeInvalidConfig, message)
}

// NewProviderError creates a provider error
func NewProviderError(message string) *TokenSmithError {
	return New(ErrCodeProviderError, message)
}

// NewPolicyError creates a policy error
func NewPolicyError(message string) *TokenSmithError {
	return New(ErrCodePolicyEvaluation, message)
}

// NewValidationError creates a validation error
func NewValidationError(message string) *TokenSmithError {
	return New(ErrCodeValidation, message)
}

// NewInternalError creates an internal error
func NewInternalError(message string) *TokenSmithError {
	return New(ErrCodeInternal, message)
}
