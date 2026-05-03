#!/bin/sh
# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

# Only pass --config if the file exists (optional config file mode)
CONFIG_ARG=""
if [ -f "$TOKENSMITH_CONFIG" ]; then
  CONFIG_ARG="--config=$TOKENSMITH_CONFIG"
fi

exec /usr/local/bin/tokensmith serve \
  --oidc-issuer="$TOKENSMITH_OIDC_PROVIDER" \
  --issuer="$TOKENSMITH_ISSUER" \
  --port="$TOKENSMITH_PORT" \
  --cluster-id="$TOKENSMITH_CLUSTER_ID" \
  --openchami-id="$TOKENSMITH_OPENCHAMI_ID" \
  $CONFIG_ARG \
  --key-dir="$TOKENSMITH_KEY_DIR" \
  --rfc8693-bootstrap-store="$TOKENSMITH_RFC8693_BOOTSTRAP_STORE" \
  --rfc8693-refresh-store="$TOKENSMITH_RFC8693_REFRESH_STORE" \
  "$@"
