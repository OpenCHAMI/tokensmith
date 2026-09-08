# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

FROM alpine:3

# Include curl in the final image.
RUN set -ex \
    && apk update \
    && apk add --no-cache curl tini jq \
    && rm -rf /var/cache/apk/*  \
    && rm -rf /tmp/*
RUN mkdir -p /tokensmith/data

STOPSIGNAL SIGTERM

# Set environment variables with defaults. TOKENSMITH_ISSUER and
# TOKENSMITH_OIDC_PROVIDER are deliberately absent: both are required and
# must be supplied by the deployment.
ENV TOKENSMITH_CLUSTER_ID="default-cluster"
ENV TOKENSMITH_OPENCHAMI_ID="default-openchami"
ENV TOKENSMITH_CONFIG="/etc/tokensmith/config.json"
ENV TOKENSMITH_KEY_DIR="/tokensmith/data/keys"
ENV TOKENSMITH_RFC8693_BOOTSTRAP_STORE="/tokensmith/data/bootstrap"
ENV TOKENSMITH_RFC8693_REFRESH_STORE="/tokensmith/data/refresh"
ENV TOKENSMITH_PORT="8080"

VOLUME /tokensmith/keys
VOLUME /tokensmith/config
VOLUME /tokensmith/data


# Get the tokensmith service from the goreleaser build.
COPY tokensmith /usr/local/bin/
# nobody 65534:65534
USER 65534:65534

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/tokensmith"]
CMD ["serve"]
