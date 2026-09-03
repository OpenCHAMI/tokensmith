// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"strings"

	"github.com/rs/zerolog/log"
)

func (s *TokenService) logStartupSummary(addr string, tlsEnabled bool) {
	log.Info().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldEvent), string(LogEventTokenSmithStarted)).
		Str(string(LogFieldHandler), string(LogHandlerStartup)).
		Str(string(LogFieldIssuer), s.Config.Issuer).
		Str(string(LogFieldClusterID), s.Config.ClusterID).
		Str(string(LogFieldOpenCHAMIID), s.Config.OpenCHAMIID).
		Str(string(LogFieldOIDCIssuer), s.Config.OIDCIssuerURL).
		Str(string(LogFieldOIDCClientID), s.Config.OIDCClientID).
		Str(string(LogFieldOIDCClaimPolicy), string(s.Config.OIDCClaimPolicy)).
		Bool(string(LogFieldOIDCCAConfigured), strings.TrimSpace(s.Config.OIDCCAPath) != "").
		Int64(string(LogFieldMaxExchangeSessionLifetimeSeconds), int64(s.Config.MaxExchangeSessionLifetime.Seconds())).
		Str(string(LogFieldBootstrapStorePath), s.Config.RFC8693BootstrapStorePath).
		Str(string(LogFieldRefreshStorePath), s.Config.RFC8693RefreshStorePath).
		Bool(string(LogFieldTLSEnabled), tlsEnabled).
		Bool(string(LogFieldServiceIdentityMTLSEnabled), s.serviceIdentityCAPool != nil).
		Bool(string(LogFieldLocalUserMintEnabled), s.Config.EnableLocalUserMint).
		Str(string(LogFieldListenAddr), addr).
		Msg(string(LogEventTokenSmithStarted))
}
