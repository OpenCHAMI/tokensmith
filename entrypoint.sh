#!/bin/sh
# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT
exec /usr/local/bin/tokensmith serve \
  --oidc-issuer="$TOKENSMITH_OIDC_PROVIDER" \
  --issuer="$TOKENSMITH_ISSUER" \
  --port="$TOKENSMITH_PORT" \
  --cluster-id="$TOKENSMITH_CLUSTER_ID" \
  --openchami-id="$TOKENSMITH_OPENCHAMI_ID" \
  --config="$TOKENSMITH_CONFIG" \
  --key-dir="$TOKENSMITH_KEY_DIR"