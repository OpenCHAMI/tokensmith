#!/bin/sh
# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT
# Passing --config="" makes TokenSmith fall back to its built-in defaults, but
# an operator who comments TOKENSMITH_CONFIG out of their compose file gets the
# image default instead, which points at a file that may not exist -- the
# container then exits with a confusing "no such file or directory". Only pass
# the flag when a path is actually configured.
CONFIG_ARG=""
if [ -n "$TOKENSMITH_CONFIG" ]; then
  CONFIG_ARG="--config=$TOKENSMITH_CONFIG"
fi

exec /usr/local/bin/tokensmith serve \
  ${CONFIG_ARG:+"$CONFIG_ARG"} \
  --oidc-issuer="$TOKENSMITH_OIDC_PROVIDER" \
  --issuer="$TOKENSMITH_ISSUER" \
  --port="$TOKENSMITH_PORT" \
  --cluster-id="$TOKENSMITH_CLUSTER_ID" \
  --openchami-id="$TOKENSMITH_OPENCHAMI_ID" \
  --key-dir="$TOKENSMITH_KEY_DIR" \
  --rfc8693-bootstrap-store="$TOKENSMITH_RFC8693_BOOTSTRAP_STORE" \
  --rfc8693-refresh-store="$TOKENSMITH_RFC8693_REFRESH_STORE" \
  --service-identity-ca="$TOKENSMITH_SERVICE_IDENTITY_CA" \
  --tls-cert-file="$TOKENSMITH_TLS_CERT_FILE" \
  --tls-key-file="$TOKENSMITH_TLS_KEY_FILE" \
  "$@"
