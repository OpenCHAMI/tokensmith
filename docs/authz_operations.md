<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith AuthZ Operations Guide

This document provides **operational guidance** for running TokenSmith-based authorization in OpenCHAMI services.

It is **non-normative**. The normative behavior/contract is:

- [`authz_contract.md`](authz_contract.md)

Policy loading mechanics are described in:

- [`authz_policy.md`](authz_policy.md)

## What you get by default

- A **baseline embedded Casbin model + policy** ships in TokenSmith.
- If you do not configure a policy directory, the baseline policy is the effective policy.
- Policy is loaded at **process start**; **no hot reload** in v1.

## Policy distribution (mounting fragments)

### When to use fragments

Use filesystem policy fragments when you need to:

- extend the baseline RBAC (e.g., add additional objects/actions),
- add temporary allowances during a migration,
- override/deny permissions by removing or avoiding grants.

### Directory + filename convention

Mount a directory into each service (e.g., via Kubernetes ConfigMap/Secret/volume), and point the service at it via:

- `TOKENS_MITH_POLICY_DIR` (preferred)
- `AUTHZ_POLICY_DIR` (compat)

TokenSmith loads `*.csv` fragments in **lexical order** by filename.

Recommended convention:

- `00-baseline.csv` (do not use; baseline is embedded)
- `10-org.csv`
- `20-site.csv`
- `90-emergency.csv`

### Kubernetes example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openchami-authz-policy
  labels:
    app.kubernetes.io/name: openchami-authz-policy

data:
  10-site.csv: |
    # Example: grant viewer read of a custom object
    p, role:viewer, custom:status, read
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metadata-service
spec:
  template:
    spec:
      containers:
      - name: metadata-service
        env:
        - name: TOKENS_MITH_POLICY_DIR
          value: /etc/tokensmith/authz
        volumeMounts:
        - name: authz-policy
          mountPath: /etc/tokensmith/authz
          readOnly: true
      volumes:
      - name: authz-policy
        configMap:
          name: openchami-authz-policy
```

## Rollout strategy: off → shadow → enforce

Recommended staged rollout (per service):

1. **off**
   - Authorization disabled.
   - Use this while wiring middleware and validating authn/principal extraction.

2. **shadow**
   - Authorization evaluated but not enforced.
   - Monitor for shadow denials and fix principals/policy gaps.
   - Keep this enabled long enough to cover expected operational use cases.

3. **enforce**
   - Denied/indeterminate/error decisions block with HTTP 403.
   - Ensure you have an incident rollback plan (switch back to shadow/off).

## Confirming what policy is running (policy_version)

TokenSmith computes a deterministic policy hash referred to as `policy_version`.

You should validate `policy_version` when:

- rolling out new policy fragments,
- troubleshooting unexpected access decisions,
- verifying that all replicas are running the same policy.

Where to find `policy_version`:

- Service startup logs during policy load.
- AuthZ decision logs/metrics emitted by the middleware.
- The 403 response body returned by the AuthZ middleware in enforce mode.

If different pods show different `policy_version` values, verify that the same fragments are mounted everywhere and that pods were restarted.

## Troubleshooting

### Symptom: policy changes have no effect

Most common causes:

- Service not restarted (no hot reload).
- Fragment not mounted at the expected path.
- Wrong env var set (`TOKENS_MITH_POLICY_DIR` vs `AUTHZ_POLICY_DIR`).
- Filename does not match `*.csv` or has unexpected ordering.

### Symptom: requests are unexpectedly denied in enforce mode

Checklist:

- Confirm the principal identity:
  - user principals need `sub` and roles/groups.
  - service principals should map to role `service`.
- Confirm the object/action mapping used by the service matches the policy.
- Compare `policy_version` in the denial body to what you expect.

### Symptom: shadow mode shows denials but everything still works

This is expected: shadow mode does not block.

Use shadow denials to:

- identify missing role/group mappings,
- identify missing policy grants for legitimate workflows,
- estimate impact before switching to enforce.

## Example policy snippets (roles and service principals)

The baseline policy already includes core RBAC. These examples show *typical* additional snippets you might deploy.

### Admin (explicit full CRUD)

```csv
# Admin is typically already granted full access by baseline.
p, role:admin, *, *
```

### Operator (read/write, no delete)

```csv
# Example: allow operator to update boot parameters
p, role:operator, boot:parameters, update
# Example: do NOT grant delete
# (absence of a delete rule results in deny)
```

### Viewer (read-only)

```csv
p, role:viewer, metadata:nodes, read
p, role:viewer, boot:configs, read
```

### Service-to-service principal (service role)

How service identities are expressed depends on your AuthN/principal extraction.

A common pattern is to map a service client id (or azp) into the `service` role.

```csv
# Map a specific service principal into role:service
# (exact subject string depends on your service principal mapping)
# Example subject style used in the contract examples: "role:service".
# If you use grouping policies, you may also use Casbin's g() relationships.
#
# Example using g() to link a service principal to the role:
# g, service:boot-service, role:service
#
# Then grant the role permissions:
p, role:service, metadata:nodes, read
```
