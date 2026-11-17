package tokenservice

import (
	"crypto/rsa"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/openchami/tokensmith/pkg/deviceauth"
	"github.com/rs/zerolog/log"
)

// ConfigureDeviceAuth enables GitLab device authorization before serving.
// Nil leaves existing routes and credentials unchanged. No HTTP endpoint can
// change policy.
func (s *TokenService) ConfigureDeviceAuth(config *deviceauth.Config) error {
	if config == nil {
		return nil
	}
	if s.deviceAuth != nil || config.Validate() != nil || config.ClusterIssuer != s.Issuer {
		return deviceauth.ErrDenied
	}
	// Use the existing key and JWKS endpoint without changing legacy algorithms.
	// The user-session token contract is PS256; reject incompatible configuration
	// rather than publishing another algorithm for the same shared signing key.
	if s.TokenManager.GetSigningAlgorithm() != "PS256" {
		return deviceauth.ErrDenied
	}
	secret, err := readDeviceAuthVerifier(config.VerifierFile)
	if err != nil {
		return deviceauth.ErrDenied
	}
	// GitHub, Entra and Google profiles are transport-only login stubs.
	// Enabling one requires its own identity adapter and permission policy.
	provider, err := deviceauth.NewGitLab(*config, secret)
	if err != nil {
		return deviceauth.ErrDenied
	}
	key, err := s.TokenManager.GetKeyManager().GetPrivateKey()
	if err != nil {
		return deviceauth.ErrDenied
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return deviceauth.ErrDenied
	}
	keyID, err := s.TokenManager.GetKeyManager().GetKid()
	if err != nil {
		return deviceauth.ErrDenied
	}
	signer, err := deviceauth.NewKeyRing(keyID, rsaKey)
	if err != nil {
		return deviceauth.ErrDenied
	}
	authority, err := deviceauth.New(*config, provider, signer, func(record deviceauth.Audit) {
		log.Info().Interface("device_auth", record).Msg("device_authority")
	})
	if err != nil {
		return deviceauth.ErrDenied
	}
	s.deviceAuth = authority
	return nil
}

func readDeviceAuthVerifier(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", deviceauth.ErrDenied
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", deviceauth.ErrDenied
	}
	const maxSecretBytes = 16 * 1024
	secret, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil || len(secret) > maxSecretBytes || strings.TrimSpace(string(secret)) == "" {
		return "", deviceauth.ErrDenied
	}
	return strings.TrimSpace(string(secret)), nil
}

// Route device-authorization requests before the legacy request logger. Rejected
// query strings or User-Agent headers may contain credentials and must not be logged.
// Existing OAuth exchange, revocation, local-peer and mTLS routes are untouched.
func (s *TokenService) withDeviceAuthRoutes(legacy http.Handler) http.Handler {
	if s.deviceAuth == nil {
		return legacy
	}
	deviceAuth := middleware.Timeout(60 * time.Second)(middleware.Recoverer(s.deviceAuth))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/device-auth" || strings.HasPrefix(r.URL.Path, "/device-auth/") {
			deviceAuth.ServeHTTP(w, r)
			return
		}
		legacy.ServeHTTP(w, r)
	})
}
