// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

func (s *TokenService) writeOAuthTokenResponse(w http.ResponseWriter, statusCode int, response OAuthTokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Msg("Failed to write OAuth token response")
	}
}

func (s *TokenService) writeOAuthError(w http.ResponseWriter, statusCode int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(OAuthErrorResponse{
		Error:            code,
		ErrorDescription: description,
	}); err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Msg("Failed to write OAuth error response")
	}
}
