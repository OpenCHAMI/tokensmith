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

## Policy version hash

TokenSmith computes a deterministic SHA-256 hash over:

- the embedded model text, and
- the concatenated **effective policy lines** after loading baseline + fragments (normalized for whitespace/newlines)

This hash is surfaced via TokenSmith APIs as `PolicyVersion()` and is intended for logs/metrics and troubleshooting.

## Trust boundary

TokenSmith does **not** verify signatures on policy fragments in v1.

The policy directory is treated as **trusted deploy-time configuration** (e.g., ConfigMap/volume mounted by cluster admins).

If signature verification is required later, TokenSmith will add it as an extension without breaking this loading contract.
