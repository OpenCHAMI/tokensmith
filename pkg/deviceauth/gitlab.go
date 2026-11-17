// Package deviceauth authenticates users who approve GitLab OAuth device grants.
// It verifies user identity and project membership, not the device itself.
// Caller-asserted identity, roles, issuer, audience and project are not trusted.
// Only the GitLab adapter is implemented here. GitHub, Entra and Google profiles
// in pkg/deviceflow are transport-only login stubs without these authority checks.
package deviceauth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openchami/tokensmith/internal/httpjson"
	"github.com/openchami/tokensmith/pkg/deviceflow"
)

// Device and Credential share the provider-neutral device grant wire format.
type Device = deviceflow.Device
type Credential = deviceflow.Token

// Identity is the immutable user ID and verified remaining OAuth lifetime.
type Identity struct {
	UserID    int64
	ExpiresAt time.Time
}

// GitLab uses only a configured HTTPS origin, certificate validation, bounded
// bodies and timeouts. Never include response bodies/URLs/transport errors in
// returned errors: OAuth material may occur in any of them.
type GitLab struct {
	config   Config
	client   *http.Client
	verifier string
}

// NewGitLab binds all calls to one configured GitLab origin and application.
func NewGitLab(config Config, verifier string) (*GitLab, error) {
	if config.Validate() != nil || strings.TrimSpace(verifier) == "" {
		return nil, ErrDenied
	}
	return &GitLab{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Never forward OAuth or membership credentials to a redirect target.
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied },
		},
		verifier: strings.TrimSpace(verifier),
	}, nil
}
func (g *GitLab) call(ctx context.Context, path, bearer string, form url.Values, out any) (int, error) {
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method = http.MethodPost
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, g.config.Issuer+path, body)
	if err != nil {
		return 0, ErrDenied
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := g.client.Do(request)
	if err != nil {
		return 0, ErrDenied
	}
	defer func() { _ = response.Body.Close() }()
	if out != nil && httpjson.Decode(response.Body, out) != nil {
		return response.StatusCode, ErrDenied
	}
	return response.StatusCode, nil
}

// Start requests a device challenge with only the read_user OAuth scope.
func (g *GitLab) Start(ctx context.Context) (Device, error) {
	flow, err := g.deviceClient()
	if err != nil {
		return Device{}, ErrDenied
	}
	device, err := flow.Start(ctx)
	// Preserve the tighter GitLab contract, independent of the generic RFC layer.
	if err != nil || device.Expires > 300 || device.Interval > 300 {
		return Device{}, ErrDenied
	}
	return device, nil
}

func (g *GitLab) deviceClient() (*deviceflow.Client, error) {
	config := deviceflow.GitLab(g.config.Issuer, g.config.ClientID)
	return deviceflow.NewWithTransport(config, g.client.Transport)
}

// validateGrant applies GitLab identity requirements after the common exchange.
// Other providers may legitimately omit refresh or expiry; this adapter may not.
func (g *GitLab) validateGrant(ctx context.Context, credential Credential, err error) (Credential, error) {
	if err == nil && (credential.Error == "authorization_pending" || credential.Error == "slow_down") {
		return credential, nil
	}
	if err != nil || credential.Access == "" || credential.Refresh == "" ||
		credential.Scope != "read_user" || credential.Expires <= 0 || credential.IDToken != "" {
		if credential.Access != "" {
			_ = g.Revoke(ctx, credential.Access)
		}
		return Credential{}, ErrDenied
	}
	return credential, nil
}

// Poll exchanges the private device code after the polling interval.
func (g *GitLab) Poll(ctx context.Context, code string) (Credential, error) {
	flow, err := g.deviceClient()
	if err != nil {
		return Credential{}, ErrDenied
	}
	credential, err := flow.Poll(ctx, code)
	return g.validateGrant(ctx, credential, err)
}

// Refresh rotates the private GitLab credential; the authority serializes calls.
func (g *GitLab) Refresh(ctx context.Context, refresh string) (Credential, error) {
	flow, err := g.deviceClient()
	if err != nil {
		return Credential{}, ErrDenied
	}
	credential, err := flow.Refresh(ctx, refresh)
	// Pending/slow_down are meaningful only while polling device approval.
	if credential.Error != "" {
		return Credential{}, ErrDenied
	}
	return g.validateGrant(ctx, credential, err)
}

// Verify checks both the OAuth application and the currently active user.
func (g *GitLab) Verify(ctx context.Context, access string, now time.Time) (Identity, error) {
	var info struct {
		Application struct {
			UID string `json:"uid"`
		} `json:"application"`
		Owner   int64    `json:"resource_owner_id"`
		Scope   []string `json:"scope"`
		Created int64    `json:"created_at"`
		Expires int64    `json:"expires_in"`
	}
	status, err := g.call(ctx, "/oauth/token/info", access, nil, &info)
	if err != nil || status != 200 || info.Application.UID != g.config.ClientID || info.Owner <= 0 || len(info.Scope) != 1 || info.Scope[0] != "read_user" || info.Created <= 0 || info.Created > now.Unix() || info.Expires <= 0 || info.Expires > 86400 {
		return Identity{}, ErrDenied
	}
	// token/info expires_in is remaining lifetime, not the original TTL.
	// Anchor at request start and reserve one second for upstream rounding.
	expiresAt := now.Add(time.Duration(info.Expires-1) * time.Second)
	if !now.Before(expiresAt) {
		return Identity{}, ErrDenied
	}
	var user struct {
		ID    int64  `json:"id"`
		State string `json:"state"`
	}
	status, err = g.call(ctx, "/api/v4/user", access, nil, &user)
	if err != nil || status != 200 || user.ID != info.Owner || user.State != "active" {
		return Identity{}, ErrDenied
	}
	return Identity{UserID: user.ID, ExpiresAt: expiresAt}, nil
}

// Membership reads effective project membership, including inherited access.
// It uses the separate verifier credential, not the user's read_user token.
func (g *GitLab) Membership(ctx context.Context, user int64) (int, error) {
	var member struct {
		ID    int64 `json:"id"`
		Level int   `json:"access_level"`
	}
	status, err := g.call(ctx, "/api/v4/projects/"+strconv.FormatInt(g.config.ProjectID, 10)+"/members/all/"+strconv.FormatInt(user, 10), g.verifier, nil, &member)
	if err != nil || status != 200 || member.ID != user {
		return 0, ErrDenied
	}
	return member.Level, nil
}

// Revoke retires a GitLab access token without exposing it in errors.
func (g *GitLab) Revoke(ctx context.Context, access string) error {
	status, err := g.call(ctx, "/oauth/revoke", "", url.Values{"client_id": {g.config.ClientID}, "token": {access}}, nil)
	if err != nil || status != 200 {
		return ErrDenied
	}
	return nil
}
