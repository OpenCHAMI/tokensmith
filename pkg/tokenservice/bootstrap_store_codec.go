package tokenservice

import (
	"encoding/json"
	"time"
)

type bootstrapPolicyDisk struct {
	ID                   string        `json:"id"`
	Subject              string        `json:"subject"`
	Audience             string        `json:"audience"`
	Scopes               []string      `json:"scopes"`
	TTL                  time.Duration `json:"ttl"`
	RefreshTTL           time.Duration `json:"refresh_ttl"`
	TokenHash            string        `json:"token_hash"`
	CreatedAt            time.Time     `json:"created_at"`
	ExpiresAt            time.Time     `json:"expires_at"`
	ConsumedAt           *time.Time    `json:"consumed_at,omitempty"`
	ConsumedByIP         string        `json:"consumed_by_ip,omitempty"`
	ReplayAttempts       []time.Time   `json:"replay_attempts,omitempty"`
	BindingIdentifier    string        `json:"binding_identifier,omitempty"`
	IssuedAccessTokenID  string        `json:"issued_access_token_id,omitempty"`
	IssuedRefreshTokenID string        `json:"issued_refresh_token_id,omitempty"`
}

func policyToDisk(policy *BootstrapTokenPolicy) bootstrapPolicyDisk {
	return bootstrapPolicyDisk{policy.ID, policy.Subject, policy.Audience, append([]string(nil), policy.Scopes...), policy.TTL, policy.RefreshTTL, policy.TokenHash, policy.CreatedAt, policy.ExpiresAt, cloneTime(policy.ConsumedAt), policy.ConsumedByIP, append([]time.Time(nil), policy.ReplayAttempts...), policy.BindingIdentifier, policy.IssuedAccessTokenID, policy.IssuedRefreshTokenID}
}

func decodeBootstrapPolicy(data []byte) (*BootstrapTokenPolicy, error) {
	var disk bootstrapPolicyDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}
	var legacy BootstrapTokenPolicy
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, err
	}
	if disk.TokenHash == "" {
		return cloneBootstrapPolicy(&legacy), nil
	}
	return cloneBootstrapPolicy(&BootstrapTokenPolicy{disk.ID, disk.Subject, disk.Audience, disk.Scopes, disk.TTL, disk.RefreshTTL, disk.TokenHash, disk.CreatedAt, disk.ExpiresAt, disk.ConsumedAt, disk.ConsumedByIP, disk.ReplayAttempts, disk.BindingIdentifier, disk.IssuedAccessTokenID, disk.IssuedRefreshTokenID}), nil
}
