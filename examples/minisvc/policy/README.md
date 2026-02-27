<!--
SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors

SPDX-License-Identifier: MIT
-->

# minisvc policy

This directory contains **standard Casbin artifacts** used by `examples/minisvc`.

Files:

- `model.conf`: Casbin model (RBAC + keyMatch2 + REST-ish actions)
- `policy.csv`: permissions (p, sub, obj, act)
- `grouping.csv`: role membership (g, user, role)

Casbin search terms that apply directly:

- "Casbin RBAC"
- "Casbin keyMatch2"
- "Casbin model.conf"
- "Casbin policy.csv"

## What this policy does

- `/public` is configured as **public bypass** in middleware config (not in Casbin)
- `/protected/mapper` is authorized via **explicit RouteMapper** and mapped to:
  - object: `minisvc:mapper`
  - action: `read`
- `/protected/path/*` is authorized via **path/method style**:
  - object: request path (e.g. `/protected/path/widgets/123`)
  - action: REST-ish action derived from method:
    - GET/HEAD -> `read`
    - POST/PUT/PATCH -> `write`
    - DELETE -> `delete`

### Example identities

- JWT with `sub=user1` and `roles=["viewer"]` can:
  - read `/protected/path/*`
  - read `minisvc:mapper`
- JWT with `sub=user2` and `roles=["operator"]` can:
  - read/write `/protected/path/*`
  - read `minisvc:mapper`

Role membership is also shown in `grouping.csv` as an alternative to using roles
embedded in JWTs.
