// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMaxExchangeSessionLifetime(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{name: "empty uses default", value: "", want: DefaultMaxExchangeSessionLifetime},
		{name: "duration", value: "168h", want: 7 * 24 * time.Hour},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1h", wantErr: true},
		{name: "malformed", value: "one day", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseMaxExchangeSessionLifetime(test.value)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
