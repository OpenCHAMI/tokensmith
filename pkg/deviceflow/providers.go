package deviceflow

import (
	"net/url"
	"strings"
)

// GitLab returns a grant profile for a GitLab HTTPS origin, including self-hosted
// instances. Identity and project membership still need separate verification.
func GitLab(origin, clientID string) Config {
	return Config{
		ClientID:        clientID,
		Scope:           "read_user",
		DeviceEndpoint:  origin + "/oauth/authorize_device",
		TokenEndpoint:   origin + "/oauth/token",
		VerificationURI: origin + "/oauth/device",
	}
}

// GitHub returns the GitHub.com device-grant transport profile.
// This is a transport-only stub for TokenSmith device login: user/application
// verification, organization/team/repository permission mapping and session
// integration are not implemented. Local fixtures cover the grant exchange only.
// Enable device flow in the application. An enterprise instance may need an
// explicit Config with different endpoints.
func GitHub(clientID, scope string) Config {
	return Config{
		ClientID:        clientID,
		Scope:           scope,
		DeviceEndpoint:  "https://github.com/login/device/code",
		TokenEndpoint:   "https://github.com/login/oauth/access_token",
		VerificationURI: "https://github.com/login/device",
	}
}

// Entra returns a tenant-specific public-client device-grant transport profile.
// This is a transport-only stub for TokenSmith device login: tenant/application/
// user verification, group/app-role mapping and session integration are not
// implemented. Local fixtures cover the grant exchange only. Use a fixed tenant
// ID for single-tenant policy; accepting common/organizations is an identity-policy
// decision, not something the grant transport can safely decide for the caller.
func Entra(tenant, clientID, scope string) (Config, error) {
	if tenant == "" || strings.ContainsAny(tenant, "/?#%\\") || tenant == "." || tenant == ".." {
		return Config{}, ErrProtocol
	}
	base := "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0"
	return Config{
		ClientID:        clientID,
		Scope:           scope,
		DeviceEndpoint:  base + "/devicecode",
		TokenEndpoint:   base + "/token",
		VerificationURI: "https://microsoft.com/devicelogin",
	}, nil
}

// Google returns the limited-input-device grant transport profile.
// This is a transport-only stub for TokenSmith device login: user/application
// verification, membership/role policy and session integration are not implemented.
// Local fixtures cover the grant exchange only. Google requires an eligible
// client registration and restricts the scopes available to this grant type.
// Supply any registration-required client secret through private provisioning.
func Google(clientID, scope string) Config {
	return Config{
		ClientID:        clientID,
		Scope:           scope,
		DeviceEndpoint:  "https://oauth2.googleapis.com/device/code",
		TokenEndpoint:   "https://oauth2.googleapis.com/token",
		VerificationURI: "https://www.google.com/device",
	}
}
