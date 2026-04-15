<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith troubleshooting guide

This guide addresses common issues and how to diagnose and resolve them.

## Token exchange fails

### Symptom: "401 Unauthorized" when exchanging OIDC code for TokenSmith JWT

**Cause**: TokenSmith is not correctly configured or cannot reach the OIDC provider.

**Diagnosis**:

1. Verify OIDC provider is running:
   ```bash
   curl -s "https://your-oidc-issuer/.well-known/openid-configuration" | jq .
   ```
   If this fails, your OIDC provider is unreachable.

2. Check TokenSmith logs for OIDC discovery errors:
   ```
   level=error msg="oidc discovery failed" issuer="..." error="..."
   ```

3. Verify client credentials:
   ```bash
   echo "Configured issuer: $(echo $OIDC_ISSUER_URL)"
   echo "Configured client ID: $(echo $OIDC_CLIENT_ID)"
   # Secret is not echoed for safety
   ```

4. Test token validation with a known OIDC token:
   ```bash
   # If you have a valid token from your OIDC provider:
   curl -X POST "http://localhost:8080/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=<OIDC_TOKEN>&subject_token_type=urn:ietf:params:oauth:token-type:id_token"
   ```

**Resolution**:

1. Ensure OIDC provider is reachable from TokenSmith:
   - Check firewall rules
   - Check network connectivity
   - Verify DNS resolution

2. Verify OIDC client credentials:
   - Compare `$OIDC_CLIENT_ID` with the OIDC provider configuration
   - Verify `$OIDC_CLIENT_SECRET` is correct (try rotating the secret in OIDC provider if unsure)

3. Check token validity:
   - Ensure the OIDC token is not expired
   - Verify the token includes required claims

---

## Local user token generation fails

### Symptom: "user-token create" command fails with permission error or endpoint not found

**Cause 1**: `--enable-local-user-mint` was not set when TokenSmith started.

**Cause 2**: TokenSmith was started on a non-default port or from a remote machine.

**Diagnosis**:

1. Verify `--enable-local-user-mint` flag was used:
   ```bash
   ps aux | grep tokensmith
   # Look for "enable-local-user-mint" in the process command
   ```

2. Check if the local admin endpoint is responding:
   ```bash
   curl -i "http://localhost:8080/admin/oidc/config"
   ```
   - **200 OK**: Admin endpoint is accessible
   - **403 Forbidden**: Request is not from localhost (non-local access)
   - **404 Not Found**: TokenSmith is not running or admin endpoint is disabled

3. Verify port configuration:
   ```bash
   # Check which port TokenSmith is listening on
   netstat -tlnp | grep tokensmith
   # Or use the status command if available
   tokensmith server status
   ```

**Resolution**:

1. Restart TokenSmith with the flag:
   ```bash
   tokensmith serve --enable-local-user-mint
   ```

2. If running remote TokenSmith, tunnel through localhost:
   ```bash
   # On remote machine (via SSH)
   ssh -L 8080:localhost:8080 user@remote-tokensmith-host
   # Then run locally:
   tokensmith user-token create --subject "user" --scopes "admin"
   ```

3. If using non-standard port, configure CLI:
   ```bash
   export TOKENSMITH_ADMIN_URL="http://localhost:9090"
   tokensmith user-token create ...
   ```

---

## OIDC provider reconfiguration fails

### Symptom: "oidc configure" command fails with "already configured" or discovery error

**Cause 1**: Existing provider is configured and `--replace-existing` flag is missing.

**Cause 2**: New OIDC provider is unreachable or has invalid configuration.

**Diagnosis**:

1. Check current OIDC configuration:
   ```bash
   tokensmith oidc status
   # Shows: issuer, client ID, and whether local user minting is enabled
   ```

2. Attempt a dry-run to validate without applying:
   ```bash
   tokensmith oidc configure \
     --issuer-url "https://new-provider.example.com" \
     --client-id "new-client" \
     --dry-run
   # Should show: "would create" or "would replace"
   # If it fails here, new provider is invalid
   ```

3. Manually test new provider discovery:
   ```bash
   curl -s "https://new-provider.example.com/.well-known/openid-configuration" | jq .
   ```

**Resolution**:

1. If replacing an existing provider, pass the flag:
   ```bash
   tokensmith oidc configure \
     --issuer-url "https://new-provider.example.com" \
     --client-id "new-client" \
     --replace-existing
   ```

2. Verify new provider is reachable:
   - Check firewall rules
   - Check DNS resolution
   - Verify provider URL is correct (no typos)

3. Provide client secret at runtime:
   ```bash
   export OIDC_CLIENT_SECRET="new-secret"
   tokensmith oidc configure \
     --issuer-url "https://new-provider.example.com" \
     --client-id "new-client" \
     --replace-existing
   ```

---

## TokenSmith JWT verification fails

### Symptom: Client receives valid TokenSmith JWT but services reject it with "invalid signature" or "invalid claims"

**Cause**: Service is using wrong signing key or outdated key.

**Diagnosis**:

1. Check TokenSmith signing key rotation:
   ```bash
   # Review TokenSmith logs for key rotation events
   journalctl -u tokensmith -g "key rotation\|signing key"
   ```

2. Verify service validation config:
   - Is the service using JWKS endpoint? Check if it's refreshing keys.
   - Is the service using static public keys? They may have become stale.

3. Extract and inspect the token:
   ```bash
   # Decode (not verify) the token to see claims
   echo "<JWT_TOKEN>" | cut -d. -f2 | base64 -d | jq .
   ```

4. Check signing algorithm:
   ```bash
   # Extract header
   echo "<JWT_TOKEN>" | cut -d. -f1 | base64 -d | jq .
   # Should show "alg": "ES256" or similar
   ```

**Resolution**:

1. Ensure service is refreshing JWKS keys:
   - If using tokensmith pkg/authn middleware: automatic
   - If custom validation: implement periodic JWKS refresh

2. If using static keys, rotate and redeploy services.

3. Verify token was signed with correct key:
   - Use the `/jwks` endpoint to get the current key: `curl http://localhost:8080/jwks`
   - Match the `kid` (key ID) in token header with active key

---

## Claims are missing or incorrect

### Symptom: TokenSmith JWT is missing expected claims or claims have wrong values

**Cause**: OIDC provider not returning required claims or TokenSmith not mapping them correctly.

**Diagnosis**:

1. Decode the incoming OIDC token (before exchange):
   ```bash
   # If you have a raw OIDC token from your provider:
   echo "<OIDC_TOKEN>" | cut -d. -f2 | base64 -d | jq .
   ```

2. Decode the resulting TokenSmith JWT:
   ```bash
   echo "<TOKENSMITH_JWT>" | cut -d. -f2 | base64 -d | jq .
   ```

3. Check the mapping contract:
   - See [Claim Reference](./claim-reference.md) for which claims TokenSmith includes
   - Verify OIDC provider includes required user claims

**Resolution**:

1. Ensure OIDC provider includes the claims:
   - Check OIDC provider client scopes (e.g., `email`, `profile`)
   - Verify user is in correct groups (if groups claims are expected)

2. Restart services consuming the token to clear caches.

3. Review custom claim mappers in your service (if applicable).

---

## Remote access to admin endpoints fails

### Symptom: "Forbidden" when calling `oidc configure` from a remote machine

**Cause**: Admin endpoints are local-only (by design). They only accept requests from `127.0.0.1` or `::1`.

**Diagnosis**:

```bash
# Verify endpoint is rejecting non-local requests
curl -v "http://remote-tokensmith:8080/admin/oidc/config"
# Should return: 403 Forbidden
```

**Resolution**:

1. **If TokenSmith is on a remote machine**, use SSH tunneling:
   ```bash
   ssh -L 8080:localhost:8080 user@remote-tokensmith
   # Then locally:
   tokensmith oidc configure ...
   ```

2. **If TokenSmith is in a container or cluster**, exec into the pod:
   ```bash
   # Kubernetes example
   kubectl exec -it deployment/tokensmith -- \
     tokensmith oidc configure \
       --issuer-url "https://..." \
       --client-id "..." \
       --replace-existing
   ```

3. **AVOID**: Do not expose admin endpoints publicly. Loopback-only access is a security boundary.

---

## Logs not showing enough detail

### Symptom: TokenSmith logs don't show enough information to diagnose an issue

**Diagnosis**:

Check log level:
```bash
echo $LOG_LEVEL
# Should be: debug, info, warn, error
```

**Resolution**:

1. Enable debug logging:
   ```bash
   export LOG_LEVEL="debug"
   tokensmith serve
   ```

2. Search logs for specific errors:
   ```bash
   # On systemd:
   journalctl -u tokensmith -p err

   # Docker:
   docker logs <container> | grep -i error

   # Kubernetes:
   kubectl logs deployment/tokensmith | grep -i error
   ```

3. Collect logs before/after a failing operation:
   ```bash
   # Clear logs
   journalctl -u tokensmith --vacuum-time=1m
   # Perform operation
   # Collect logs
   journalctl -u tokensmith -n 100 --no-pager > tokensmith-logs.txt
   ```

---

## Performance issues

### Symptom: Token exchange or validation is slow

**Cause 1**: OIDC provider discovery or token validation is slow.

**Cause 2**: JWKS endpoint is not caching.

**Diagnosis**:

1. Measure OIDC provider latency:
   ```bash
   time curl -s "https://your-oidc-issuer/.well-known/openid-configuration" > /dev/null
   ```

2. Check JWKS cache hit rate:
   ```bash
   # Review logs for "jwks_cache" entries
   journalctl -u tokensmith | grep jwks_cache
   ```

3. Profile token exchange:
   ```bash
   # Measure individual request latency with curl
   time curl -X POST "http://localhost:8080/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=<TOKEN>&subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
     -w "\nTotal time: %{time_total}s\n" -o /dev/null
   ```

**Resolution**:

1. **Slow OIDC provider**: Reduce latency by moving provider closer or improving network connectivity.

2. **JWKS cache misses**: Verify JWKS endpoint is responding with correct cache headers.

3. **Add caching layer**: Use HTTP caching proxy between TokenSmith and OIDC provider (only if safe for your use case).

---

## Related documentation

- [Token Flows](./token-flows.md) — Understanding upstream vs local token flows
- [Claim Reference](./claim-reference.md) — Available claims in TokenSmith JWTs
- [CLI Reference](./cli-reference.md) — Command-line interface reference
- [Environment Reference](./env-reference.md) — Environment variable reference
- [Security Notes](./security-notes.md) — Security considerations
