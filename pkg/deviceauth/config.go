package deviceauth

import (
	"errors"
	"net/url"
)

// ErrDenied deliberately contains no upstream error, URL or credential value.
var ErrDenied = errors.New("device authorization denied")

// Config fixes the identity provider and session policy before serving requests.
// All durations use seconds. Zero values do not enable a permissive policy.
// VerifierFile is consumed by tokenservice; the provider receives its contents.
type Config struct {
	Issuer          string `json:"issuer"` // GitLab HTTPS origin; no path or query.
	ClientID        string `json:"client_id"`
	ProjectID       int64  `json:"project_id"`
	ClusterIssuer   string `json:"cluster_issuer"` // Issuer of the resulting cluster JWT.
	Audience        string `json:"audience"`
	VerifierFile    string `json:"verifier_file"` // Private project-membership API credential.
	CacheSeconds    int64  `json:"cache_seconds"` // Maximum age of an effective-membership result.
	TokenSeconds    int64  `json:"token_seconds"`
	SkewSeconds     int64  `json:"skew_seconds"` // Total issuer-to-consumer clock error budget.
	AbsoluteSeconds int64  `json:"absolute_seconds"`
}

// Validate enforces a five-minute worst-case revocation budget:
// membership cache age + issued token lifetime + total clock error <= 300s.
// The ten-hour session limit is independent of GitLab's refresh-token lifetime.
func (c Config) Validate() error {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return ErrDenied
	}
	if c.ClientID == "" || c.ProjectID <= 0 || c.ClusterIssuer == "" ||
		c.Audience == "" || c.VerifierFile == "" {
		return ErrDenied
	}
	if c.CacheSeconds < 0 || c.CacheSeconds > 90 || c.TokenSeconds <= 0 ||
		c.TokenSeconds > 180 || c.SkewSeconds < 0 || c.SkewSeconds > 30 ||
		c.AbsoluteSeconds != 36000 || c.CacheSeconds+c.TokenSeconds+c.SkewSeconds > 300 {
		return ErrDenied
	}

	return nil
}
