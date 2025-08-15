package token

import "errors"

var (
	// ErrTokenExpired indicates that the token has expired
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenNotValidYet indicates that the token is not yet valid
	ErrTokenNotValidYet = errors.New("token is not yet valid")

	// ErrMissingIssuer indicates that the issuer claim is missing
	ErrMissingIssuer = errors.New("missing issuer claim")

	// ErrMissingSubject indicates that the subject claim is missing
	ErrMissingSubject = errors.New("missing subject claim")

	// ErrMissingAudience indicates that the audience claim is missing
	ErrMissingAudience = errors.New("missing audience claim")

	// ErrInvalidSignature indicates that the token signature is invalid
	ErrInvalidSignature = errors.New("invalid token signature")

	// ErrInvalidToken indicates that the token is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidKey indicates that the key is invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrTokenIntrospectionFailed indicates that token introspection failed
	ErrTokenIntrospectionFailed = errors.New("token introspection failed")
)
