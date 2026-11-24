// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog/log"
)

func bearerToken(header string) (string, bool) { return oidc.ParseBearerToken(header) }
func stringInSlice(s string, list []string) bool {
	for _, it := range list {
		if it == s {
			return true
		}
	}
	return false
}
func logAuthNFailure(r *http.Request, reason string, err error) {
	logAuthNFailureWithFields(r, reason, err, nil)
}
func logAuthNFailureWithFields(r *http.Request, reason string, err error, extra map[string]any) {
	evt := log.Warn().Str("component", "authn_middleware").Str("reason", reason).Str("method", r.Method).Str("path", r.URL.Path)
	if err != nil {
		evt = evt.Err(err)
	}
	if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
		evt = evt.Str("request_id", requestID)
	}
	for k, v := range extra {
		evt = evt.Interface(k, v)
	}
	evt.Msg("JWT authentication failed")
}
func extractAudienceValues(claims jwt.MapClaims) []string {
	audRaw, ok := claims["aud"]
	if !ok {
		return nil
	}
	switch v := audRaw.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, it := range v {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
