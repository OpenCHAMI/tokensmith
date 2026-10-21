// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"time"
)

var ErrOAuthLifetimeTooShort = errors.New("oauth lifetime is less than one second")

func oauthLifetimeSeconds(duration time.Duration) (int, error) {
	if duration < time.Second {
		return 0, ErrOAuthLifetimeTooShort
	}
	return int(duration / time.Second), nil
}
