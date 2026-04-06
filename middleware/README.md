<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Middleware Package Notice

TokenSmith provides JWT authentication in `pkg/authn`, with authorization handled by `pkg/authz`.

## Migrate To

1. JWT authentication: `github.com/openchami/tokensmith/pkg/authn`
2. Authorization middleware/policy: `github.com/openchami/tokensmith/pkg/authz`

See setup docs:

- `docs/migration.md`
- `docs/getting-started.md`
- `docs/casbin-first-guide.md`
