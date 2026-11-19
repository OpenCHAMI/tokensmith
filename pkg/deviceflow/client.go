// Package deviceflow exchanges OAuth device grants without assigning identity or
// permissions. Provider-specific identity checks must run before issuing tokens.
package deviceflow

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openchami/tokensmith/internal/httpjson"
)

var (
	// Errors deliberately exclude URLs, credentials and upstream response bodies.
	ErrProtocol = errors.New("device authorization failed")
	ErrDenied   = errors.New("device authorization declined")
	ErrExpired  = errors.New("device authorization expired")
)

// Config is trusted server configuration, never supplied by the login caller.
// VerificationURI pins the browser destination independently of token endpoints.
// ClientSecret, when required, belongs in private provisioning, not public config.
type Config struct {
	ClientID        string
	ClientSecret    string
	Scope           string
	DeviceEndpoint  string
	TokenEndpoint   string
	VerificationURI string
}

// Device contains both the private polling code and the public approval prompt.
// A broker must retain Code privately and expose only UserCode and URI.
type Device struct {
	Code     string `json:"device_code"`
	UserCode string `json:"user_code"`
	URI      string `json:"verification_uri"`
	Expires  int64  `json:"expires_in"`
	Interval int64  `json:"interval"`
}

// Token is a provider credential, not proof of identity or cluster authority.
// Refresh, Expires and IDToken are optional in the protocol. The identity adapter
// must impose its own requirements and verify any ID token before trusting it.
type Token struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Type    string `json:"token_type"`
	Expires int64  `json:"expires_in"`
	Scope   string `json:"scope"`
	IDToken string `json:"id_token,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Client owns one immutable provider configuration. It does not follow redirects
// or choose endpoints from responses. Requests always use verified HTTPS.
type Client struct {
	config Config
	http   *http.Client
}

func validHTTPS(raw string) bool {
	endpoint, err := url.Parse(raw)
	return err == nil && endpoint.Scheme == "https" && endpoint.Host != "" &&
		endpoint.User == nil && endpoint.RawQuery == "" && endpoint.Fragment == ""
}

// New constructs a client without making a network request.
func New(config Config) (*Client, error) {
	return NewWithTransport(config, nil)
}

// NewWithTransport allows an administrator-provided trust transport (for example,
// a private CA). Redirect and timeout policy stay owned by the grant client.
// A nil transport uses the standard library's verified HTTPS transport.
func NewWithTransport(config Config, transport http.RoundTripper) (*Client, error) {
	if config.ClientID == "" || !validHTTPS(config.DeviceEndpoint) ||
		!validHTTPS(config.TokenEndpoint) || !validHTTPS(config.VerificationURI) {
		return nil, ErrProtocol
	}
	return &Client{
		config: config,
		http: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrProtocol },
		},
	}, nil
}

// post bounds every response before parsing it. A generic error prevents an
// upstream server (or transport error) from copying credentials into logs.
func (c *Client) post(ctx context.Context, endpoint string, form url.Values, out any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, ErrProtocol
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json") // GitHub otherwise returns form data.
	response, err := c.http.Do(request)
	if err != nil {
		return 0, ErrProtocol
	}
	defer func() { _ = response.Body.Close() }()
	if httpjson.Decode(response.Body, out) != nil {
		return response.StatusCode, ErrProtocol
	}
	return response.StatusCode, nil
}

// Start requests an approval challenge. Google uses verification_url; normalize
// that documented alias, but reject a response with conflicting destinations.
func (c *Client) Start(ctx context.Context) (Device, error) {
	var response struct {
		Device
		VerificationURL string `json:"verification_url"`
	}
	status, err := c.post(ctx, c.config.DeviceEndpoint, url.Values{
		"client_id": {c.config.ClientID},
		"scope":     {c.config.Scope},
	}, &response)
	device := response.Device
	if device.URI == "" {
		device.URI = response.VerificationURL
	} else if response.VerificationURL != "" && response.VerificationURL != device.URI {
		return Device{}, ErrProtocol
	}
	if device.Interval == 0 {
		device.Interval = 5 // RFC 8628 default when the provider omits interval.
	}
	if err != nil || status != http.StatusOK || device.Code == "" || device.UserCode == "" ||
		device.URI != c.config.VerificationURI || device.Expires <= 0 || device.Expires > 1800 ||
		device.Interval < 1 || device.Interval > device.Expires {
		return Device{}, ErrProtocol
	}
	return device, nil
}

func (c *Client) grant(ctx context.Context, form url.Values) (Token, error) {
	form.Set("client_id", c.config.ClientID)
	if c.config.ClientSecret != "" {
		form.Set("client_secret", c.config.ClientSecret)
	}
	var token Token
	status, err := c.post(ctx, c.config.TokenEndpoint, form, &token)
	if err != nil || (status != http.StatusOK && status != http.StatusBadRequest) {
		return Token{}, ErrProtocol
	}
	if token.Error != "" {
		if token.Access != "" || token.Refresh != "" || token.IDToken != "" {
			return Token{}, ErrProtocol
		}
		switch token.Error {
		case "authorization_pending", "slow_down":
			return Token{Error: token.Error}, nil
		case "access_denied", "authorization_declined":
			return Token{}, ErrDenied
		case "expired_token":
			return Token{}, ErrExpired
		default:
			return Token{}, ErrProtocol
		}
	}
	if status != http.StatusOK || token.Access == "" || !strings.EqualFold(token.Type, "Bearer") || token.Expires < 0 {
		return Token{}, ErrProtocol
	}
	return token, nil
}

// Poll performs one request. The caller owns the transaction deadline and must
// wait at least Device.Interval seconds, adding five seconds after slow_down.
func (c *Client) Poll(ctx context.Context, code string) (Token, error) {
	if code == "" {
		return Token{}, ErrProtocol
	}
	return c.grant(ctx, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {code},
	})
}

// Refresh performs one exchange. Serialize calls because refresh tokens may
// rotate. A missing refresh token requires a fresh device approval instead.
func (c *Client) Refresh(ctx context.Context, refresh string) (Token, error) {
	if refresh == "" {
		return Token{}, ErrProtocol
	}
	return c.grant(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
}
