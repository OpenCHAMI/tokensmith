package tokenservice

import "fmt"

func validateBootstrapPolicy(policy *BootstrapTokenPolicy, policies map[string]*BootstrapTokenPolicy) error {
	if policy == nil || policy.ID == "" || policy.TokenHash == "" || policy.ExpiresAt.IsZero() {
		return fmt.Errorf("bootstrap policy identity and expiry are required")
	}
	for hash, existing := range policies {
		if hash != policy.TokenHash && existing.ID == policy.ID {
			return fmt.Errorf("bootstrap policy identity already belongs to another token hash")
		}
	}
	return nil
}

func validateRefreshFamily(family *RefreshTokenFamily) error {
	if family == nil || family.FamilyID == "" || family.CurrentTokenHash == "" || family.ExpiresAt.IsZero() {
		return fmt.Errorf("refresh token family identity and expiry are required")
	}
	if containsHash(family.ConsumedGenerationHashes, family.CurrentTokenHash) {
		return fmt.Errorf("refresh token current hash cannot be consumed")
	}
	seen := make(map[string]struct{}, len(family.ConsumedGenerationHashes))
	for _, hash := range family.ConsumedGenerationHashes {
		if hash == "" {
			return fmt.Errorf("refresh token consumed hash is required")
		}
		if _, exists := seen[hash]; exists {
			return fmt.Errorf("refresh token consumed hash is duplicated")
		}
		seen[hash] = struct{}{}
	}
	return nil
}
