<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith AuthZ Policy Loading

TokenSmith embeds a **baseline Casbin model + policy** so that every consumer has a safe, consistent RBAC default.

Deployments **MAY** extend the baseline with **policy fragments** (Casbin policy CSV snippets) mounted into the service container.

## Baseline

- Model: embedded in TokenSmith
- Policy: embedded in TokenSmith

If no policy directory is configured, TokenSmith loads the baseline only.

## Policy load lifecycle (v1)

TokenSmith loads its policy at **process startup**.

- **Hot reload is not supported in v1.**
- If you change the effective policy (baseline is updated by upgrading TokenSmith, or fragments are changed on disk), you **MUST restart** the service to pick up changes.

## Policy fragments (filesystem)

### Enable fragment loading

Set one of:

- `TOKENS_MITH_POLICY_DIR` (preferred)
- `AUTHZ_POLICY_DIR` (compat)

to a directory containing policy fragment files.

### Discovery rules

- TokenSmith loads files matching `*.csv` (including `*.policy.csv`) from the directory.
- Fragments are loaded in **lexical order** by filename.

### Example Kubernetes deployment

Mount a ConfigMap containing CSV fragments:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: boot-service-authz-policy
data:
  10-local.csv: |
    # grant viewer read access to an additional object
    p, role:viewer, boot:status, read
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: boot-service
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
          name: boot-service-authz-policy
```

## Policy version hash (policy_version)

TokenSmith computes a deterministic SHA-256 hash (`policy_version`) over the **effective Casbin artifacts**:

- effective `model.conf` text (normalized newlines), and
- merged policy CSV bytes, and
- merged grouping CSV bytes.

The merge order for fragment directories is deterministic (lexicographic path order), so `policy_version` is stable across restarts even when filesystem enumeration order differs.

`policy_version` is intended for logs/metrics and troubleshooting.

It does **not** represent runtime authorization behavior by itself:

- it does not include enforcement mode (OFF/SHADOW/ENFORCE)
- it does not include mapping strategy (explicit RouteMapper vs path/method style)

Those should be logged alongside `policy_version` so operators can interpret decisions correctly.

## Trust boundary

TokenSmith does **not** verify signatures on policy fragments in v1.

The policy directory is treated as **trusted deploy-time configuration** (e.g., ConfigMap/volume mounted by cluster admins).

If signature verification is required later, TokenSmith will add it as an extension without breaking this loading contract.
