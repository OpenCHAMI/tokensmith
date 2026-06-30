// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

func (s *TokenService) RevokeWithCascade(ctx context.Context, jti string, expiresAt time.Time) error {
	s.revocationStore.Revoke(jti, expiresAt)

	log.Info().
		Str("component", "tokenservice").
		Str("jti", jti).
		Time("expires_at", expiresAt).
		Msg("Token revoked")

	if s.hierarchyStorage != nil {
		children, err := s.hierarchyStorage.ListHierarchiesByParentID(ctx, jti)
		if err != nil {
			log.Warn().
				Err(err).
				Str("parent_jti", jti).
				Msg("Failed to list children for cascade revocation (non-fatal)")
			return nil
		}

		if len(children) > 0 {
			log.Info().
				Str("parent_jti", jti).
				Int("child_count", len(children)).
				Msg("Cascading revocation to child tokens")

			for _, child := range children {
				if err := s.RevokeWithCascade(ctx, child.ChildTokenID, expiresAt); err != nil {
					log.Warn().
						Err(err).
						Str("parent_jti", jti).
						Str("child_jti", child.ChildTokenID).
						Msg("Failed to revoke child token (continuing cascade)")
				}
			}
		}
	}

	return nil
}
