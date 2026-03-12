<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith Casbin-first AuthN/AuthZ guide

TokenSmith provides **drop-in `net/http` middleware** for JWT authentication (AuthN) and Casbin authorization (AuthZ).

**Casbin is the standard interface**:

- Operators and service owners edit **Casbin** `model.conf`, `policy.csv`, and `grouping.csv`.
- TokenSmith provides presets and helpers, but does **not** invent a TokenSmith-specific policy DSL.

If you are troubleshooting, these search terms apply directly:

- "Casbin RBAC"
- "Casbin model.conf"
- "Casbin policy.csv"
- "Casbin grouping policy"
- "Casbin keyMatch2"
- "Casbin rbac_with_domains"
- "Casbin functions keyMatch2 regexMatch"

## Division of responsibilities

### TokenSmith owns

- AuthN JWT validation behavior and safe defaults.
- Principal extraction and a stable principal representation in request context.
- AuthZ mode semantics: `OFF` | `SHADOW` | `ENFORCE`.
- Deny-by-default behavior for **unmapped** requests in `ENFORCE`.
- Consistent deny response schema (`authz.deny.v1`).
- Deterministic policy discovery/merge order and `policy_version` hashing.
- A documented, opt-in escape hatch to customize the underlying Casbin enforcer.

### Services own

- Choosing a mapping strategy:
  - **Explicit RouteMapper**: service decides `(object, action[, domain])` per route.
  - **Path/method style**: service uses request path + method normalization and writes Casbin matchers like `keyMatch2`.
- Declaring which routes are public (bypass authz).
- Defining the service’s object/action taxonomy (if using explicit mapping).
- Wiring middleware ordering and request-id propagation.

## Recommended middleware ordering

1. request-id middleware (optional, but recommended)
2. TokenSmith AuthN (JWT validation; populates principal)
3. TokenSmith AuthZ (Casbin)
4. application handler

## AuthZ modes

| Mode | Evaluate Casbin? | Deny requests? | Intended use |
|------|------------------|----------------|--------------|
| OFF | no | no | initial wiring / break-glass |
| SHADOW | yes (when mapped) | no | observe impact before enforcing |
| ENFORCE | yes (when mapped) | yes | normal secured operation |

Notes:

- Public-bypassed requests are never evaluated.
- In `ENFORCE`, **unmapped** routes are denied by default (unless explicitly configured otherwise).

## Inputs to Casbin: two supported styles

### A) Explicit mapping (RouteMapper)

You implement a mapper:

- `Map(r *http.Request, p Principal) -> RouteDecision`

Where a `RouteDecision` includes:

- `Public` (bypass AuthZ)
- `Mapped` (whether the request was mapped)
- `Object`, `Action`, optional `Domain`

This is ideal when:

- your routes are generated (e.g., Fabrica CRUD), and
- you have a stable object/action taxonomy.

### B) Path/method (Casbin-native)

TokenSmith feeds Casbin with:

- `object = normalized URL path` (no query string)
- `action = normalized method` (literal or REST-ish)
- optional `domain`

This is ideal when:

- you want to write Casbin policies over URLs using matchers like `keyMatch2`, and
- you want operators to troubleshoot with standard Casbin docs.

See `examples/minisvc` for both styles.

## Why both `policy.csv` and `grouping.csv`

Casbin RBAC separates **permissions** from **membership**:

- `policy.csv` contains permission rules (`p` lines), typically:
   - `p, <role-or-subject>, <object>, <action>`
- `grouping.csv` contains grouping rules (`g` lines), typically:
   - `g, <subject>, <role>`

In practice:

- Keep authorization intent in `policy.csv` (what can be done).
- Keep subject/role assignment in `grouping.csv` (who gets which role).

`grouping.csv` is optional if your AuthN/mapper already injects roles directly into the principal and your matcher/policy uses those role strings directly. Even then, keeping grouping in Casbin can improve operator clarity and troubleshooting.

Both effective policy and grouping content are included in `policy_version` hashing.

## Policy layout, discovery, merge order

TokenSmith can load policy from:

- **embedded baseline** (optional / minimal), plus
- filesystem **overrides/fragments**.

### Filesystem discovery

See `docs/authz_policy.md` for the normative operational behavior. In particular:

- fragment directories are read in a deterministic, lexical ordering
- file filtering and ordering are deterministic
- symlinks are handled consistently (see `docs/authz_policy.md`)

### `policy_version`

TokenSmith computes a deterministic SHA-256 hash over:

- effective `model.conf` bytes, and
- effective merged policy CSV bytes, and
- effective merged grouping CSV bytes.

`policy_version` is intended for:

- logs, deny responses, and troubleshooting
- proving that all pods/replicas are running the same effective policy

`policy_version` is not an authorization decision by itself; you must interpret it alongside:

- mode (OFF/SHADOW/ENFORCE)
- mapping strategy (explicit vs path/method)

## Troubleshooting workflow

1. Confirm mode (`OFF` vs `SHADOW` vs `ENFORCE`).
2. Confirm your mapping style:
   - explicit mapper: verify the object/action your mapper produces
   - path/method: verify the normalized path and method→action mapping
3. Confirm the principal:
   - id/type/roles (do not expect raw JWT claims)
4. Compare `policy_version`:
   - if it differs across pods, you likely have inconsistent mounts or missing restarts
5. For Casbin evaluation issues:
   - enable SHADOW mode + decision logging
   - use standard Casbin troubleshooting patterns (validate model, matcher, policy format)

## Related docs

- Frozen wire contract (normative): `docs/authz-spec.md`
- AuthZ contract (normative): `docs/authz_contract.md`
- Policy loading + `policy_version`: `docs/authz_policy.md`
- Ops guide: `docs/authz_operations.md`
- Examples:
  - `examples/minisvc`
