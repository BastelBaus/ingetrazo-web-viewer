# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The IngeTrazo web viewer and MCP gateway: users, OAuth, folder rights and
# pages, Python standard library only, no IngeTrazo and no X server. The
# rendering and modelling happen in engines: containers of the
# ingetrazo-docker image (https://github.com/BastelBaus/ingetrazo-docker),
# reached over an internal network (ENGINE_URLS, MCP_ENGINE_URL).
#
#   viewer  the live web viewer (default)
#   mcp     the MCP gateway

# ---- three.js for the viewer's 3D view ------------------------------------------
# A pinned release (MIT), checked against its SHA-256, served by the viewer
# itself (no CDN at view time).
FROM python:3.15-slim-bookworm AS three
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN set -e; \
    base=https://cdn.jsdelivr.net/npm/three@0.170.0; \
    dir=/three; \
    fetch() { mkdir -p "$(dirname "$dir/$2")"; \
              curl -fsSL --retry 3 -o "$dir/$2" "$base/$1"; \
              echo "$3  $dir/$2" | sha256sum -c --quiet -; }; \
    fetch build/three.module.min.js three.module.min.js 08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7; \
    fetch examples/jsm/loaders/GLTFLoader.js addons/loaders/GLTFLoader.js 45139faddd5aaf48ed2d62203d976e5cbd703db1a592de40527f9f6cf58abd44; \
    fetch examples/jsm/controls/OrbitControls.js addons/controls/OrbitControls.js 80efaadea4f8a636a65fb0bd08bfef62f3d93a0bb94e2e7500f23176c5c07f4e; \
    fetch examples/jsm/utils/BufferGeometryUtils.js addons/utils/BufferGeometryUtils.js c25b7930e570e9ec56173cd3b866ec8d2e10016630db3937efb439daf1cedbf6; \
    fetch LICENSE LICENSE 4c40a1ef62450b857c3b2aaf294936304cd552d965fbcd9d32d4c5bcf4ba4454

# ---- the image ---------------------------------------------------------------------
FROM python:3.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini curl \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY mcp_http/ /opt/ingetrazo-web-viewer/mcp_http/
COPY viewer/ /opt/ingetrazo-web-viewer/viewer/
COPY --from=three /three /opt/ingetrazo-web-viewer/viewer/static/three
RUN chmod -R a+rX /opt/ingetrazo-web-viewer

RUN useradd --create-home --uid 1000 ingetrazo \
 && mkdir -p /data /cache /state /users /engine \
 && chown ingetrazo:ingetrazo /data /cache /state /users /engine

ARG WEB_VIEWER_REF=dev
ENV WEB_VIEWER_VERSION=$WEB_VIEWER_REF \
    INGETRAZO_DATA=/data \
    INGETRAZO_CACHE=/cache \
    INGETRAZO_STATE=/state \
    PYTHONPATH=/opt/ingetrazo-web-viewer

# Every module imports (stdlib only).
RUN python -c "import viewer.server, mcp_http.server, mcp_http.remote, mcp_http.users"

USER ingetrazo
WORKDIR /home/ingetrazo
VOLUME ["/cache", "/state", "/users"]
EXPOSE 8765 8080
ENV HEALTH_PORT=8080

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["viewer"]

HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
  CMD curl -fs "http://127.0.0.1:${HEALTH_PORT:-8080}/healthz" > /dev/null || exit 1
