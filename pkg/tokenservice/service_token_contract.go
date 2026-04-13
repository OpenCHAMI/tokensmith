// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

const (
	BootstrapTokenEnvVar = "TOKENSMITH_BOOTSTRAP_TOKEN"

	RefreshTokenUseClaim = "refresh_token"
	RefreshTokenUseField = "token_use"
	RefreshTargetField   = "target_service"
	RefreshScopesField   = "scopes"
	RefreshOneTimeField  = "refresh_one_time"
	RefreshAudience      = "tokensmith"
)
