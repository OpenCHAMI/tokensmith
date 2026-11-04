package tokenservice

import "errors"

// Close releases persistent-store resources owned by the service.
func (s *TokenService) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	if s.bootstrapTokenStore != nil {
		errs = append(errs, s.bootstrapTokenStore.Close())
	}
	if s.refreshTokenStore != nil {
		errs = append(errs, s.refreshTokenStore.Close())
	}
	if s.serviceIdentityPolicyStore != nil {
		errs = append(errs, s.serviceIdentityPolicyStore.Close())
	}
	return errors.Join(errs...)
}
