// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maximumErrorBodyBytes = 8 << 10
	maximumTokenBodyBytes = 1 << 20
)

type tokenRequestError struct {
	stage     string
	status    int
	oauthCode string
	truncated bool
	sent      bool
	cause     error
}

func (e *tokenRequestError) Error() string {
	parts := []string{"token request " + e.stage}
	if e.status != 0 {
		parts = append(parts, fmt.Sprintf("status=%d", e.status))
	}
	if e.oauthCode != "" {
		parts = append(parts, "oauth_error="+e.oauthCode)
	}
	if e.truncated {
		parts = append(parts, "body_truncated=true")
	}
	return strings.Join(parts, " ")
}

func (e *tokenRequestError) Unwrap() error { return e.cause }

func isGuaranteedPreSendBootstrapError(err error) bool {
	var requestErr *tokenRequestError
	return errors.As(err, &requestErr) && !requestErr.sent && requestErr.stage == "transport"
}

func requestWasSent(err error) bool {
	var requestErr *tokenRequestError
	return errors.As(err, &requestErr) && requestErr.sent
}

func (c *ServiceClient) requestServiceToken(ctx context.Context, grantType string) error {
	form := url.Values{}
	switch grantType {
	case "bootstrap":
		bootstrapToken := c.currentBootstrapToken()
		if bootstrapToken == "" {
			return fmt.Errorf("%w: set %s or WithBootstrapToken", ErrMissingBootstrapToken, BootstrapTokenEnvVar)
		}
		form.Set("grant_type", GrantTypeTokenExchange)
		form.Set("subject_token", bootstrapToken)
		form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	case "refresh":
		c.mu.RLock()
		refreshToken := strings.TrimSpace(c.refreshToken)
		c.mu.RUnlock()
		if refreshToken == "" {
			return ErrMissingRefreshToken
		}
		form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
		form.Set("refresh_token", refreshToken)
	default:
		return fmt.Errorf("unsupported internal grant type: %s", grantType)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokensmithURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return &tokenRequestError{stage: "request", cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = c.doTokenRequest(req)
	if grantType == "bootstrap" && (err == nil || requestWasSent(err)) {
		c.burnBootstrapToken()
	}
	return err
}

func (c *ServiceClient) requestServiceIdentitySession(ctx context.Context, certPath, keyPath string) error {
	if err := validateServiceIdentityURL(c.tokensmithURL); err != nil {
		return err
	}
	mtlsClient, err := c.clientWithMutualTLS(certPath, keyPath)
	if err != nil {
		return err
	}
	defer mtlsClient.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokensmithURL+"/service-identity/session", strings.NewReader("{}"))
	if err != nil {
		return &tokenRequestError{stage: "request", cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doTokenRequestWithClient(mtlsClient, req)
}

func (c *ServiceClient) doTokenRequest(req *http.Request) error {
	return c.doTokenRequestWithClient(c.client, req)
}

func (c *ServiceClient) doTokenRequestWithClient(client *http.Client, req *http.Request) error {
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{
		WroteHeaders: func() { sent.Store(true) },
		WroteRequest: func(httptrace.WroteRequestInfo) { sent.Store(true) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return &tokenRequestError{stage: "transport", sent: sent.Load(), cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, truncated, readErr := readBounded(resp.Body, maximumErrorBodyBytes)
		if readErr != nil {
			return &tokenRequestError{stage: "response-body", status: resp.StatusCode, sent: true, cause: readErr}
		}
		return &tokenRequestError{stage: "response", status: resp.StatusCode, oauthCode: allowedOAuthCode(body), truncated: truncated, sent: true}
	}
	body, truncated, readErr := readBounded(resp.Body, maximumTokenBodyBytes)
	if readErr != nil {
		return &tokenRequestError{stage: "response-body", status: resp.StatusCode, sent: true, cause: readErr}
	}
	if truncated {
		return &tokenRequestError{stage: "decode", status: resp.StatusCode, truncated: true, sent: true}
	}
	var token OAuthTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return &tokenRequestError{stage: "decode", status: resp.StatusCode, sent: true, cause: err}
	}
	if strings.TrimSpace(token.AccessToken) == "" || token.ExpiresIn <= 0 || strings.TrimSpace(token.RefreshToken) == "" || token.RefreshExpiresIn <= 0 {
		return &tokenRequestError{stage: "decode", status: resp.StatusCode, sent: true}
	}
	now := time.Now().UTC()
	c.mu.Lock()
	c.token = &ServiceToken{Token: token.AccessToken, ExpiresAt: now.Add(time.Duration(token.ExpiresIn) * time.Second)}
	c.refreshToken = strings.TrimSpace(token.RefreshToken)
	c.refreshExpiresAt = now.Add(time.Duration(token.RefreshExpiresIn) * time.Second)
	c.mu.Unlock()
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, false, err
	}
	return body[:min(len(body), int(limit))], len(body) > int(limit), nil
}

func allowedOAuthCode(body []byte) string {
	var response struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&response) != nil {
		return ""
	}
	switch response.Error {
	case "access_denied", "invalid_client", "invalid_grant", "invalid_request", "invalid_scope", "invalid_token", "server_error", "temporarily_unavailable", "unsupported_grant_type":
		return response.Error
	default:
		return ""
	}
}

func (c *ServiceClient) burnBootstrapToken() {
	c.mu.Lock()
	c.bootstrapToken = ""
	c.bootstrapBurned = true
	c.mu.Unlock()
}

func (c *ServiceClient) doTargetRequest(req *http.Request) error {
	noRedirect := *c.client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return fmt.Errorf("target service request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, truncated, readErr := readBounded(resp.Body, maximumErrorBodyBytes)
		if readErr != nil {
			return fmt.Errorf("target service response body failed: status=%d", resp.StatusCode)
		}
		if truncated {
			return fmt.Errorf("target service response failed: status=%d body_truncated=true", resp.StatusCode)
		}
		return fmt.Errorf("target service response failed: status=%d", resp.StatusCode)
	}
	_, truncated, readErr := readBounded(resp.Body, maximumTokenBodyBytes)
	if readErr != nil {
		return errors.New("target service response body failed")
	}
	if truncated {
		return errors.New("target service response body too large")
	}
	return nil
}
