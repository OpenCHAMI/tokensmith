<!-- SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC -->
<!-- SPDX-License-Identifier: MIT -->

# GitLab device authorization

`pkg/deviceauth` verifies GitLab identity and effective project membership using
[the shared device-grant transport](device-authorization.md). GitLab application
and project policy are separate from the reusable OAuth exchange.

## Provider support

GitLab is the only implemented device-authorization identity/membership adapter.
GitHub, Entra and Google profiles in `pkg/deviceflow` are **transport-only login
stubs**: their grant exchange is fixture-tested, but their identity verification,
permission mapping and device-login/session integration are not implemented.
Each needs a separate adapter and explicit cluster-role policy before enabling
login; a missing adapter or mapping must never imply administrator access.

The existing `/oauth/exchange` endpoint uses separate OIDC validation and
claim/scope policy. This adapter's membership checks do not apply to that path.

## Identity and permission checks

The provider answers two separate questions:

1. Which active GitLab user approved this OAuth application? A `read_user`
   credential checks the application and immutable user ID.
2. What can that user do in the configured project? A separate, private verifier
   credential reads `/members/all/ID`, including inherited membership.

The server configuration selects the HTTPS origin, application and project.
Requests cannot select those values or their own role. Redirects are refused;
errors never copy GitLab response bodies, URLs or credentials.

The configuration reserves at most 90 seconds of membership cache, 180 seconds
of cluster-token life and 30 seconds of total clock error. Their sum cannot
exceed five minutes. Session approval lasts exactly ten hours; renewal cannot
move that deadline. These constraints bound the lifetime of session approval and
cached authority.

Tests use a local HTTPS GitLab fixture, including redirects, wrong applications,
wrong users, blocked accounts, expired tokens and membership lookup failures.
No GitLab account, cluster access or secrets are required.
