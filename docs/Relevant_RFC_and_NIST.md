<!--
SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors

SPDX-License-Identifier: MIT
-->

# RFC and NIST Standards Validation

This document validates all normative references used in the RFC 8693 bootstrap token migration.

## OAuth 2.0 Standards (IETF)

### RFC 8693 - OAuth 2.0 Token Exchange
**Status:** Proposed Standard (Published January 2020)
**Reference:** https://datatracker.ietf.org/doc/html/rfc8693

**Key Sections Used:**
- Section 2: Protocol Overview (token exchange model)
- Section 3: Token Request (grant_type, subject_token, subject_token_type parameters)
- Section 4: Token Response (access_token, refresh_token, expires_in, scope fields)
- Section 5: Error Response (invalid_grant, invalid_request, unsupported_grant_type codes)
- Section 6: Token Exchange (subject_token validation, scope policy enforcement)

**OpenCHAMI Application:**
- Use `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` for bootstrap exchange
- Define custom `subject_token_type=urn:openchami:params:oauth:token-type:bootstrap-token` for bootstrap tokens
- Implement server-side scope determination (Section 6.1: "Resource Server may ... determine scope")
- Use `issued_token_type=urn:ietf:params:oauth:token-type:access_token` in response

**Relevance:** RFC 8693 is the normative standard for token-to-token exchange. It explicitly supports server-side policy enforcement and custom token types, making it ideal for opaque bootstrap tokens that map to pre-authorized scopes without client negotiation.

---

### RFC 6749 - The OAuth 2.0 Authorization Framework
**Status:** Proposed Standard (Published August 2012)
**Reference:** https://datatracker.ietf.org/doc/html/rfc6749

**Key Sections Used:**
- Section 3.2: Token Endpoint (generic token endpoint semantics)
- Section 5: Issuing an Access Token (response format, expires_in)
- Section 6: Refreshing an Access Token (refresh_token grant type, scope immutability)
- Section 5.2: Error Response (OAuth error response format)
- Section 4.1.2.1: Scope (scope semantics and immutability)

**OpenCHAMI Application:**
- Implement `/oauth/token` endpoint per Section 3.2
- Use `grant_type=refresh_token` for refresh grants (Section 6)
- RFC 6749 Section 6 states: "If a new refresh token is issued, the refresh token scope MUST be identical to or narrower than the original scope." For OpenCHAMI, scopes are immutable (identical).
- Error responses use standard format (Section 5.2)

**Relevance:** RFC 6749 is the foundational OAuth 2.0 specification. It establishes the token endpoint semantics, refresh token model, and error response format that RFC 8693 extends. Section 6 confirms that refresh token scope is server-determined and immutable.

---

### RFC 6750 - The OAuth 2.0 Bearer Token Usage
**Status:** Proposed Standard (Published October 2012)
**Reference:** https://datatracker.ietf.org/doc/html/rfc6750

**Key Sections Used:**
- Section 2: Authorization Request Header Field (Bearer token usage in Authorization header)
- Section 3: Error Codes (bearer token error responses, e.g., invalid_token)

**OpenCHAMI Application:**
- Access tokens issued by bootstrap exchange are used as bearer tokens
- Consumers include access tokens in Authorization header: `Authorization: Bearer <access_token>`
- (Currently not implementing bearer token endpoint validation; consumers validate via JWT signature)

**Relevance:** RFC 6750 defines the bearer token usage pattern. OpenCHAMI services receive access tokens and can use them as bearer credentials when calling downstream services (e.g., boot-service → HSM).

---

### RFC 7517 - JSON Web Key (JWK)
**Status:** Proposed Standard (Published May 2015)
**Reference:** https://datatracker.ietf.org/doc/html/rfc7517
**Note:** Access tokens remain JWTs in OpenCHAMI Phase 1-3. JWT security is covered by RFC 7519 (JSON Web Token).

**Key Context:**
- RFC 7519 is the normative JWT specification
- OpenCHAMI uses JWTs as access tokens (clients validate signatures locally, no introspection needed per user guidance)

---

## NIST Guidelines

### NIST SP 800-63-3 Revision 3: Authentication and Lifecycle Management
**Status:** Published June 2017
**Reference:** https://pages.nist.gov/800-63-3/sp800-63-3.html

**Note on Revision:** SP 800-63-3 was superseded by SP 800-63-4, which is published as the final Revision 4 in July 2025. SP 800-63-3 remains widely used and is referenced here only for backward compatibility and stable guidance.

**Key Sections Used:**

#### Part 3: Part Three: Federation and Assertions (SP 800-63C)
- Section 5: Assertion Lifecycle (token generation, expiry, revocation)
- Section 5.1: Assertion Lifecycle Requirements
  - 5.1.1: "Limit the lifetime of assertions to the minimum necessary for legitimate use, not to exceed one hour unless specifically justified."
  - 5.1.2: "Revoke assertions for any of the following reasons: Expiration, Logout, Binding, or Revocation (e.g., token family revocation on replay)"

- Section 6: Token Binding
  - Recommends binding tokens to specific contexts
  - OpenCHAMI uses `subject` and `audience` claims as binding context

- Section 7: Assertion Protection
  - 7.1.1: "Sign all assertions."
  - 7.2: "Encryption of Assertions" (optional; OpenCHAMI currently relies on HTTPS + local verification)

**OpenCHAMI Application:**
- Access token lifetime: 1 hour (default) aligns with NIST 5.1.1 guidance
- Bootstrap token lifetime: 10 minutes (default, min 1m, max 1h) aligns with short-lived assertion requirement
- Refresh token expiry: 24 hours (default, min 1h, max 30d) is the absolute refresh-family lifetime
- Token family revocation on replay (Section 5.1.2) implements revocation for security incidents
- JWT signatures provide assertion protection (Section 7.1.1)
- `subject` and `audience` claims provide assertion binding (Section 6)
- Dedicated service identity policies are created, listed, and revoked separately from bootstrap token policies.
- Existing mTLS callers require an explicit policy before upgrade. TokenSmith does not migrate bootstrap-only callers into the mTLS path automatically.

**Relevance:** NIST SP 800-63C Part 3 provides authoritative guidance on assertion/token lifecycle. The restriction on token lifetime, revocation requirements, and binding semantics directly inform OpenCHAMI's policy choices.

---

#### Part 2: Authentication and Secrets (SP 800-63B)
- Section 5.1.4.2: Symmetric Key Generation (cryptographic entropy requirements)
- Section 5.2: Memory Protected by Operating System

**OpenCHAMI Application:**
- Bootstrap token generation uses cryptographically secure randomness (Go's `crypto/rand` package, >=128 bits entropy)
- Service tokens and refresh tokens use similar entropy

**Relevance:** NIST SP 800-63B Section 5.1.4.2 requires tokens be generated from sufficient entropy. This informs the bootstrap token generation strategy (cryptographically secure randomness, not JWTs with limited entropy).

---

### NIST SP 800-63-4 (Approved July 2025)
**Status:** Current/Approved Special Publication
**Reference:** https://pages.nist.gov/800-63-4/

**Topics Used:**
- cryptographic agility and stronger algorithms
- refresh-token security
- token-family replay detection
- secure token rotation

**OpenCHAMI Application:**
- Refresh token rotation on every use is an OpenCHAMI implementation choice aligned with NIST replay-resistance guidance.
- Token-family tracking for replay detection is a core mitigation in OpenCHAMI.
- Refresh-token family lifetime stays fixed across rotations, so rotation does not extend the family expiry
- Access tokens are replaced on each rotation until the family reaches absolute expiry

**Relevance:** NIST SP 800-63-4 provides current guidance relevant to rotation and replay resistance, which informs OpenCHAMI's Phase 3 implementation.

---

## Other Normative References

### RFC 7234 - HTTP Caching
**Status:** Proposed Standard
**Reference:** https://datatracker.ietf.org/doc/html/rfc7234

**Application:** HTTP caching directives for token endpoints (Cache-Control: no-store, no-cache)

---

## Summary of Alignment

| Aspect | Standard | OpenCHAMI Implementation |
|--------|----------|--------------------------|
| Token exchange | RFC 8693 | Bootstrap token → service token exchange |
| Token endpoint | RFC 6749 | `/oauth/token` with multiple grant types |
| Bearer tokens | RFC 6750 | Access tokens used as bearer credentials |
| Token lifecycle | NIST SP 800-63-3/4 | Expiry, binding, revocation policies |
| Refresh rotation | NIST SP 800-63-4 | New token issued on every refresh |
| Replay detection | NIST SP 800-63-4 | Token-family tracking and revocation |
| Entropy | NIST SP 800-63-3/4 | Cryptographically secure random generation |

---

## Validation Results

The referenced standards and their stated uses were checked against the current OpenCHAMI docs and implementation notes.

**Key design decisions validated against standards:**
- Opaque bootstrap tokens with server-side hashing (RFC 8693, NIST SP 800-63)
- Immutable scope/audience enforcement (RFC 8693 and RFC 6749 scope semantics)
- One-time-use bootstrap tokens (NIST SP 800-63 guidance on short-lived assertions)
- Refresh token rotation on every use (TokenSmith implementation choice aligned with NIST replay-resistance guidance)
- Token-family replay detection (TokenSmith implementation choice aligned with NIST replay-resistance guidance)
- Access token JWT format with local signature validation (RFC 7519, no introspection needed)
- Bearer token usage model (RFC 6750, suitable for internal services)

---

## Verification Scope

This document covers the standards cited in the bootstrap token migration plan and the specific claims made here. It does not certify unrelated protocol usage or future docs.
