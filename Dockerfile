# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

FROM alpine:3

# Include curl in the final image.
RUN set -ex \
    && apk update \
    && apk add --no-cache curl tini \
    && rm -rf /var/cache/apk/*  \
    && rm -rf /tmp/*

STOPSIGNAL SIGTERM

# Set environment variables with defaults
ENV TOKENSMITH_ISSUER="https://tokensmith.openchami.dev"
ENV TOKENSMITH_CLUSTER_ID="default-cluster"
ENV TOKENSMITH_OPENCHAMI_ID="default-openchami"
ENV TOKENSMITH_CONFIG="/tokensmith/config.json"
ENV TOKENSMITH_KEY_DIR="/tokensmith/keys"
ENV TOKENSMITH_OIDC_PROVIDER="http://hydra:4444"
ENV TOKENSMITH_PORT="8080"

VOLUME /tokensmith/keys
VOLUME /tokensmith/config



# Get the tokensmith service from the goreleaser build.
COPY tokensmith /usr/local/bin/
# Copy entrypoint and update perms
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# nobody 65534:65534
USER 65534:65534

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
