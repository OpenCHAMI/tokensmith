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
ENV TOKENSMITH_OIDC_PROVIDER="hydra"
ENV TOKENSMITH_PORT="8080"

VOLUME /tokensmith/keys
VOLUME /tokensmith/config



# Get the tokensmith service from the goreleaser build.
COPY tokensmith /usr/local/bin/

# nobody 65534:65534
USER 65534:65534

# Set up the command to start the service.
CMD ["/usr/local/bin/tokensmith", "serve", \
--provider=${TOKENSMITH_OIDC_PROVIDER}, \
--issuer=${TOKENSMITH_ISSUER}, \
--port=${TOKENSMITH_PORT}, \
--cluster-id=${TOKENSMITH_CLUSTER_ID}, \
--openchami-id=${TOKENSMITH_OPENCHAMI_ID}, \
--config=${TOKENSMITH_CONFIG}, \
--key-dir=${TOKENSMITH_KEY_DIR}]

ENTRYPOINT ["/sbin/tini", "--"]