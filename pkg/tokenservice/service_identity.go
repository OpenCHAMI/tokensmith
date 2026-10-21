// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	serviceIdentityAccessTTL = 3600 * time.Second
)

// ServiceIdentitySessionHandler exchanges a validated mTLS client certificate
// for an access+refresh token session using preconfigured subject policy.
func (s *TokenService) ServiceIdentitySessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	if s.serviceIdentityCAPool == nil {
		s.writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "Service identity CA is not configured")
		return
	}

	peerCerts, err := peerCertificatesFromRequest(r)
	if err != nil {
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	if err := verifyClientCertificateChain(peerCerts, s.serviceIdentityCAPool); err != nil {
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Client certificate verification failed")
		return
	}

	subject, err := serviceIdentitySubjectFromCertificate(peerCerts[0])
	if err != nil {
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	if s.serviceIdentityPolicyStore == nil {
		s.writeOAuthError(w, http.StatusForbidden, "invalid_client", "Service identity authorization failed")
		return
	}

	now := time.Now().UTC()
	policy, err := s.serviceIdentityPolicyStore.GetActive(subject, now)
	if err != nil {
		log.Warn().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "service_identity_session").
			Str("failure_class", serviceIdentityPolicyFailureClass(err)).
			Msg("Service identity authorization denied")
		s.writeOAuthError(w, http.StatusForbidden, "invalid_client", "Service identity authorization failed")
		return
	}

	accessExpiresAt := policy.ExpiresAt
	if candidate := now.Add(serviceIdentityAccessTTL); candidate.Before(accessExpiresAt) {
		accessExpiresAt = candidate
	}
	refreshExpiresAt := policy.ExpiresAt
	if candidate := now.Add(policy.RefreshTTL); candidate.Before(refreshExpiresAt) {
		refreshExpiresAt = candidate
	}
	if !now.Before(accessExpiresAt) || !now.Before(refreshExpiresAt) {
		s.writeOAuthError(w, http.StatusForbidden, "invalid_client", "Service identity authorization failed")
		return
	}
	accessExpiresIn, err := oauthLifetimeSeconds(accessExpiresAt.Sub(now))
	if err != nil {
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "An internal server error occurred")
		return
	}
	refreshExpiresIn, err := oauthLifetimeSeconds(refreshExpiresAt.Sub(now))
	if err != nil {
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "An internal server error occurred")
		return
	}

	accessToken, err := s.generateServiceIdentityTokenUntil(policy.Subject, policy.Audience, policy.Scopes, now, accessExpiresAt)
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "service_identity_session").
			Str("subject", policy.Subject).
			Msg("Failed to generate service identity access token")
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "An internal server error occurred")
		return
	}

	refreshToken, familyID, err := s.generateRefreshTokenUntil(policy.Subject, policy.Audience, policy.Scopes, now, refreshExpiresAt)
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "service_identity_session").
			Str("subject", policy.Subject).
			Msg("Failed to generate service identity refresh token")
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "An internal server error occurred")
		return
	}

	log.Info().
		Str("component", "tokenservice").
		Str("handler", "service_identity_session").
		Str("subject", policy.Subject).
		Str("audience", policy.Audience).
		Strs("scopes", policy.Scopes).
		Str("refresh_family_id", familyID).
		Msg("Service identity mTLS certificate exchanged for service session")

	s.writeOAuthTokenResponse(w, http.StatusOK, OAuthTokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        accessExpiresIn,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: refreshExpiresIn,
		Scope:            strings.Join(policy.Scopes, " "),
		IssuedTokenType:  AccessTokenTypeRFC8693,
	})
}

func serviceIdentityPolicyFailureClass(err error) string {
	switch {
	case errors.Is(err, ErrServiceIdentityPolicyNotFound):
		return "missing"
	case errors.Is(err, ErrServiceIdentityPolicyExpired):
		return "expired"
	case errors.Is(err, ErrServiceIdentityPolicyRevoked):
		return "revoked"
	default:
		return "invalid"
	}
}

func peerCertificatesFromRequest(r *http.Request) ([]*x509.Certificate, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("TLS client certificate is required")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("TLS client certificate is required")
	}
	return r.TLS.PeerCertificates, nil
}

func verifyClientCertificateChain(chain []*x509.Certificate, roots *x509.CertPool) error {
	if len(chain) == 0 {
		return fmt.Errorf("certificate chain is empty")
	}
	if roots == nil {
		return fmt.Errorf("service identity CA trust roots are not configured")
	}

	leaf := chain[0]
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if len(chain) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range chain[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	if _, err := leaf.Verify(opts); err != nil {
		return err
	}

	return nil
}

// serviceIdentitySubjectFromCertificate maps a client cert to service identity.
// Rule: use Subject.CommonName as the service subject (e.g. CN=boot-service).
func serviceIdentitySubjectFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("client certificate is required")
	}

	subject := strings.TrimSpace(cert.Subject.CommonName)
	if subject == "" {
		return "", fmt.Errorf("client certificate subject CN is required")
	}
	return subject, nil
}
