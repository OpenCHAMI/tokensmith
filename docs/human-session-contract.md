<!-- SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC -->
<!-- SPDX-License-Identifier: MIT -->

# Signed human-session contract

`pkg/token` owns `Profile`, `SelectProfile`, `HumanSessionClaims`,
`HumanSessionPolicy`, and `VerifyHumanSession`. Selection inspects unverified
routing data only: callers must verify the signature and the selected contract,
never fall back to a different validator. Selectors reject duplicate fields
(including case variants), null/non-string/unknown markers and profile conflicts.

The signed markers are `legacy-v1` and `human-session-v1`. An absent marker
selects legacy only. Legacy selection reserves `token_class=human`,
`gitlab_issuer`, `gitlab_project_id`, `gitlab_user_id`, `approved_at`, and
`membership_checked_at`; even null reserved extensions reject. Human selection
rejects legacy assurance/identity extensions. This intentional restriction
prevents marker stripping from downgrading human authority into legacy claims.
Legacy `TSClaims.ValidateAt` assurance and `session_exp <= exp` rules are unchanged.

`VerifyHumanSession(ctx, raw, HumanSessionVerification{Policy, Now, Lookup})`
requires a named trusted RSA key, PS256, JWT type, the exact signed human marker,
and fixed cluster issuer/audience, GitLab origin/project/user, role, and session
bindings. Lookup must use keys provisioned for that cluster issuer, not URLs or
issuers supplied by a token. Project and user IDs remain int64, including above
2^53. The policy contains no client IDs, credential paths, secrets or role mapping.

Expiry is strict, with no expiry leeway: membership cache + token lifetime +
total clock error remains at most 300 seconds. Approval fixes a ten-hour session
deadline, and renewal cannot extend it. Approval is neither authentication time
nor evidence of MFA. Roles are not scopes.

Device issuance now emits `human-session-v1`. Previously issued unmarked draft
human tokens must be reissued; verification intentionally rejects them.
`deviceauth.Claims` aliases shared claims, while `deviceauth.Verify` and
`KeyRing.Verify` delegate validation and retain `errors.Is(err, deviceauth.ErrDenied)`.
Use `Config.ConsumerPolicy()` to project broker configuration into consumer trust
policy. Existing helper signatures, ring key IDs, signing, rotation, and JWKS
publication are retained. Logout still denies renewal, not already issued JWTs.

This layer does not add human acceptance to `pkg/authn`; common middleware
integration and its consumer migration guide belong to the following layer.
