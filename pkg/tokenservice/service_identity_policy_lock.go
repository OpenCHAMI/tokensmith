// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"fmt"
)

func (s *ServiceIdentityPolicyStore) withStoreLock(operation func() error) (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.root)
	if err != nil {
		return fmt.Errorf("lock service identity policy store: %w", err)
	}
	defer func() {
		if err := unlockStore(lock); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	return operation()
}
