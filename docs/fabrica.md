<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Fabrica integration guide (TokenSmith AuthN/AuthZ)

This document describes how Fabrica-generated OpenCHAMI services should integrate TokenSmith’s **Casbin-first** AuthN/AuthZ middleware.

Non-goals:

- changing Fabrica itself (this is guidance only)
- defining a TokenSmith-specific policy language (Casbin is the interface)

## Summary

Fabrica-generated services typically have stable CRUD endpoints. The recommended integration is:

- Use TokenSmith **AuthN JWT middleware** to validate TokenSmith JWTs and populate a `Principal`.
- Use TokenSmith **AuthZ middleware** with an **explicit RouteMapper**.
- Keep object/action constants close to route registration (generated code), not user input.
- Write Casbin policy using those stable object/action identifiers.

For services that want URL-based policies (e.g., `keyMatch2`), see the path/method strategy in `docs/casbin-first-guide.md` and `examples/minisvc`.

## Route classification strategy

### Public endpoints

Generated services should clearly mark unauthenticated endpoints (examples):

- `/healthz`
- `/readyz`
- `/version`
- `/metrics` (deployment-dependent)

Recommended approaches:

1. Use TokenSmith AuthZ `WithPublicPrefixes` / `WithPublicRegexps` (simple), OR
2. Have your `RouteMapper` return `Public: true` for those routes.

### Protected endpoints (CRUD)

For CRUD resources, use a stable taxonomy:

- `object`: a stable string constant per resource, e.g.
  - `metadata:nodes`
  - `metadata:groups`
  - `boot:configs`
- `action`: a stable action string, e.g.
  - REST-ish: `read` | `write` | `delete`
  - or more specific verbs: `create` | `update` | `delete` | `read`

Pick one convention per service and document it.

## Recommended mapping: Method → Action (REST-ish)

A common mapping:

- `GET`/`HEAD` → `read`
- `POST`/`PUT`/`PATCH` → `write`
- `DELETE` → `delete`

This keeps policy files readable and consistent across services.

## Suggested generated code shape

### 1) Define constants

In generated code, define:

- object constants per resource
- action constants (or use shared action strings)

Example:

```go
const (
    ObjNodes  = "metadata:nodes"
    ObjGroups = "metadata:groups"

    ActRead   = "read"
    ActWrite  = "write"
    ActDelete = "delete"
)
```

### 2) Build a RouteMapper

Implement `authz.RouteMapper` in a small generated file.

Pseudo-example:

```go
func (m *routeMapper) Map(r *http.Request, p authz.Principal) authz.RouteDecision {
    // Health endpoints
    if strings.HasPrefix(r.URL.Path, "/healthz") {
        return authz.RouteDecision{Public: true}
    }

    // CRUD classification (example)
    switch {
    case r.Method == http.MethodGet && r.URL.Path == "/v1/nodes":
        return authz.RouteDecision{Mapped: true, Object: ObjNodes, Action: ActRead}

    case r.Method == http.MethodPost && r.URL.Path == "/v1/nodes":
        return authz.RouteDecision{Mapped: true, Object: ObjNodes, Action: ActWrite}

    default:
        // Unmapped -> deny-by-default in ENFORCE.
        return authz.RouteDecision{Mapped: false}
    }
}
```

Notes:

- Keep mapping **deterministic** and side-effect free.
- Avoid parsing request bodies.
- Do not accept `object`/`action` from user input.

### 3) Wire middleware

At service startup:

- construct the AuthZ engine (Casbin enforcer) once
- install AuthN then AuthZ middleware

Keep mode/config controlled by env/flags.

## Policy files in a Fabrica world

Fabrica-generated services should:

- ship a default `model.conf` (or use a TokenSmith preset)
- ship a minimal `policy.csv` / `grouping.csv` (optional)
- allow operators to mount fragment directories to extend/override

Operationally:

- TokenSmith computes and logs `policy_version` so operators can confirm what’s running.
- Merge order and symlink behavior are documented in `docs/authz_policy.md`.

## Troubleshooting checklist

- Verify your mapper’s object/action values match the policy strings.
- Confirm your service is in `SHADOW` mode while validating.
- Use Casbin-native tools/search terms:
  - "Casbin RBAC"
  - "Casbin policy order"
  - "Casbin grouping policy"

## Related docs

- `docs/casbin-first-guide.md`
- `docs/authz-spec.md`
- `docs/authz_contract.md`
- `docs/authz_policy.md`
- `examples/minisvc`
