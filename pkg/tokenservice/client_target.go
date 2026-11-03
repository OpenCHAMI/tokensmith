package tokenservice

import (
	"context"
	"fmt"
	"net/http"
)

// CallTargetService calls a target using a current service token.
func (c *ServiceClient) CallTargetService(ctx context.Context, targetURL string) error {
	if err := c.RefreshTokenIfNeeded(ctx); err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	token := c.GetServiceToken()
	if token == nil {
		return fmt.Errorf("failed to call target service: missing service token")
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	return c.doTargetRequest(req)
}
