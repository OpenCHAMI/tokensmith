package deviceauth

import (
	"errors"
	"maps"
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
	CacheSeconds    int64  `json:"cache_seconds"` // Maximum age of an effective-membership result; 1–90 seconds.
	TokenSeconds    int64  `json:"token_seconds"`
	SkewSeconds     int64  `json:"skew_seconds"` // Total issuer-to-consumer clock error budget.
	AbsoluteSeconds int64  `json:"absolute_seconds"`
	// Nil uses the default mapping; a non-nil map replaces it completely.
	// Do not omit empty maps when serializing: {} deliberately denies all roles.
	GitLabRoleMapping map[string]string `json:"gitlab_role_mapping"`
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
	if c.CacheSeconds <= 0 || c.CacheSeconds > 90 || c.TokenSeconds <= 0 ||
		c.TokenSeconds > 180 || c.SkewSeconds < 0 || c.SkewSeconds > 30 ||
		c.AbsoluteSeconds != 36000 || c.CacheSeconds+c.TokenSeconds+c.SkewSeconds > 300 {
		return ErrDenied
	}

	for source, target := range c.GitLabRoleMapping {
		switch source {
		case "owner", "maintainer", "developer", "reporter", "guest":
		default:
			return ErrDenied
		}
		switch target {
		case "admin", "operator", "viewer":
		default:
			return ErrDenied
		}
	}
	return nil
}

// clone snapshots mutable policy before an authority or middleware retains it.
func (c Config) clone() Config {
	c.GitLabRoleMapping = maps.Clone(c.GitLabRoleMapping)
	return c
}

// clusterRole maps only a verified effective GitLab access level. Unlisted or
// unknown levels are denied; a configured map never falls back to defaults.
func (c Config) clusterRole(level int) string {
	var source string
	switch level {
	case 50:
		source = "owner"
	case 40:
		source = "maintainer"
	case 30:
		source = "developer"
	case 20:
		source = "reporter"
	case 10:
		source = "guest"
	default:
		return ""
	}
	if c.GitLabRoleMapping != nil {
		return c.GitLabRoleMapping[source]
	}
	switch source {
	case "owner", "maintainer":
		return "admin"
	case "developer":
		return "operator"
	case "reporter":
		return "viewer"
	default:
		return ""
	}
}
