<!-- SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC -->
<!-- SPDX-License-Identifier: MIT -->

# OAuth device-grant client

`pkg/deviceflow` is a small, provider-neutral OAuth device-grant client. It does
not authenticate a cluster user, assign a role, issue a cluster JWT or expose an
HTTP route. An identity adapter must verify who approved the grant and what
that person may do. Obtaining an OAuth access token alone answers neither question.

## Provider support

GitHub, Microsoft Entra ID and Google are **transport-only login stubs**. Their
endpoint profiles and device-grant exchanges are implemented and tested with local
HTTPS fixtures. They do not implement user/application verification, permission
mapping or TokenSmith device-login/session integration. Completing an OAuth grant
with one of these profiles does not grant cluster access.

Each provider needs an identity and authorization adapter, an explicit cluster-role
policy, service/session integration and authorization-failure tests before it can
be enabled as a TokenSmith device-login backend. GitLab has a separate adapter;
its application and project-membership policy does not apply to the other profiles.

This support boundary concerns device login. The existing `/oauth/exchange` path
uses its separately configured OIDC validation and claim/scope policy; these
profiles neither enable that path nor add membership checks to it.

## Caller responsibilities

The caller owns the approval transaction, polling clock and absolute deadline.
Wait at least the returned interval; after `slow_down`, increase it by five seconds.
Never expose the private device code. Display only the public user code and pinned
approval URI. Store credentials privately and serialize refresh-token rotation.

| Grant profile | Difference exercised locally | Identity/authorization integration |
| --- | --- | --- |
| GitLab | `read_user`, 300-second prompt, rotating refresh token | Separate application/user and project-membership checks are required. |
| GitHub | JSON negotiation; polling errors in HTTP 200; token may omit refresh/expiry | An OAuth token is not repository/organization authority. |
| Microsoft Entra ID | Tenant endpoints; 900-second prompt; `authorization_declined`; optional ID token | Verify tenant, application and identity; map permissions explicitly. |
| Google | `verification_url`; 1800-second prompt; optional provisioned client secret | Requires an eligible device application and permitted scopes; verify identity separately. |

Optional protocol fields remain optional here. The identity adapter must reject
responses that cannot meet its security contract. In particular, no expiry is
invented for a GitHub token and an ID token is never decoded and trusted without
verification. Endpoints and browser destination come from trusted server policy;
requests and responses cannot change the destination of a credential exchange.

## Testing

Each provider profile is tested against a local, certificate-verified HTTPS
fixture. Negative cases cover redirects, TLS trust, cancellation, denial, expiry,
malformed or oversized responses and unsafe approval links.

All four fixtures run offline after Go dependencies are available:

```sh
go test -race -shuffle=on -count=1 ./pkg/deviceflow
```

These tests establish protocol handling, not successful registration, consent or
login against the real services. They do not claim four working TokenSmith login
backends. Identity verification and cluster authorization require a separate
integration for each provider.

## Protocol references

- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)
- [GitLab device authorization](https://docs.gitlab.com/api/oauth2/)
- [GitHub device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow)
- [Microsoft Entra device flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Google limited-input-device flow](https://developers.google.com/identity/protocols/oauth2/limited-input-device)
