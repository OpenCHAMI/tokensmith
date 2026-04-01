// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import "time"

const (
	BootstrapTokenUseClaim = "bootstrap_service"
	BootstrapTokenUseField = "token_use"
	BootstrapTargetField   = "target_service"
	BootstrapScopesField   = "scopes"
	BootstrapOneTimeField  = "bootstrap_one_time"
	BootstrapAudience      = "tokensmith"
	BootstrapTokenEnvVar   = "TOKENSMITH_BOOTSTRAP_TOKEN"
)

// ServiceTokenRequest is the canonical request payload for obtaining
// a short-lived service token used in internal service-to-service calls.
type ServiceTokenRequest struct {
	BootstrapToken string   `json:"bootstrap_token"`
	TargetService  string   `json:"target_service,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}

// ServiceTokenResponse is the canonical response payload for service-token minting.
type ServiceTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
